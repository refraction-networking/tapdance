use mio::Token;
use mio::unix::UnixReady;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use stream_traits::ShutStat;
use token_map::TokenMap;
use rereg_queuer::ReregQueuer;
use session_error::SessionError;
use session_id::SessionId;
use tapdance_session::TapdanceSession;

// State used by MetalIO's handling of the localhost proxy TCP connections.
pub struct CovertTCPDriver
{
    pub tok2sess: TokenMap<Rc<RefCell<TapdanceSession>>>,
    pub sessions_to_drop: VecDeque<SessionId>,
    pub rereg_queuer: ReregQueuer,
}

impl CovertTCPDriver
{
    pub fn new() -> CovertTCPDriver
    {
        CovertTCPDriver { tok2sess: TokenMap::with_initial_capacity(4096),
                          sessions_to_drop: VecDeque::new(),
                          rereg_queuer: ReregQueuer::new() }
    }
}

// Does the reading-from-Squid and writing-to-client.
// Returns false if this socket is not expected to send us further events, and
// so we should drop it from MetalIO (and drop this side's TapdanceSession Rc).
fn process_proxy_sock_event(rereg_queuer: &mut ReregQueuer,
                            td: &mut TapdanceSession, events: &UnixReady)
{
    if events.is_error() {
        error!("Squid TCP err event {:?} for client {}", events, td.session_id);
        td.end_whole_session_error(SessionError::CovertStream);
        return;
    }
    let (read_open, write_open) = td.cov.rw_is_open();

    // NOTE: the order of these 3 is important, and has bitten us before!
    // The SESSION_INIT sent in is_writable is supposed to reach the client
    // before any data, so is_writable must be handled before is_readable.
    // Then is_hup has its SESSION_CLOSE; if there was data readable at the
    // same time, then that data should be written before SESSION_CLOSE.
    if events.is_writable() {
        td.send_init_to_client(); // (idempotent)
        if write_open {
            // We do force_reads = events.is_hup() here only because a session
            // only ever has one proxy socket. If there could be a series
            // of proxy sockets, this should be false.
            td.cli_read_cov_write(rereg_queuer, events.is_hup());
        } else { // an earlier shutdown() on cov blocked; continue the shut
            if td.cov.clean_shutdown() == ShutStat::Error {
                td.end_whole_session_error(SessionError::CovertStream);
            }
        }
    }
    if events.is_readable() && read_open {
        td.cov_read_cli_write(rereg_queuer, events.is_hup());
    }
    if events.is_hup() {
        td.handle_cov_stream_hup();
    }
}

impl CovertTCPDriver
{
    // Called on proxy socket read/write/hup events.
    // The is_readable event is the Squid proxy sending data that we should pass
    // back to the client. See ClientSSLDriver for the other direction.
    pub fn process_event(&mut self, token: &Token, events: UnixReady)
    {
        let (stream_gone, session_done, session_id, maybe_drop_tok) = {
            let ref mut td = {
                if let Some(td_rc) = self.tok2sess.get_mut(token) {
                    td_rc.borrow_mut()
                } else {
                    warn!("TCP ev loop fired for {:?}; not in tokmap.", token);
                    return;
                }
            };
            process_proxy_sock_event(&mut self.rereg_queuer, td, &events);
            let stream_gone = !td.cov.stream_is_some();
            let maybe_drop_tok = if stream_gone { td.cov.take_tok() }
                                 else           { None };
            (stream_gone, td.both_half_closed(), td.session_id, maybe_drop_tok)
        };
        if stream_gone {
            if let Some(tok) = maybe_drop_tok {
                self.tok2sess.remove(tok);
            }
        }
        if session_done { self.sessions_to_drop.push_back(session_id); }
    }
}

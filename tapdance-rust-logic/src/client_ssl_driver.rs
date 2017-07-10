use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use mio::Token;
use mio::unix::UnixReady;
use time::precise_time_ns;

use client_driver::{ClientDriver, SchedSessionTimeout};
use rereg_queuer::ReregQueuer;
use session_error::SessionError;
use session_id::SessionId;
use stream_traits::ShutStat;
use tapdance_session::TapdanceSession;
use token_map::TokenMap;

pub const SESSION_TIMEOUT_NS: u64 = 30*1000*1000*1000; // 30 seconds

// State used by MetalIO's handling of the forged SSL-with-client sessions.
pub struct ClientSSLDriver
{
    pub tok2sess: TokenMap<Rc<RefCell<TapdanceSession>>>,
    pub sessions_to_drop: VecDeque<SessionId>,
    rereg_queuer: ReregQueuer,
    // Pending events for checking if a session has timed out
    session_timeouts: VecDeque<SchedSessionTimeout>,
    // Pendng events for checking if an "open" stream has timed out. Functions
    // identically to session_timeouts, but they must be separate to preserve
    // the "pushing new events onto the end always keeps it sorted" property.
    pub stream_timeouts: VecDeque<SchedSessionTimeout>,
}

fn process_ssl_events(rereg_queuer: &mut ReregQueuer, td: &mut TapdanceSession,
                      events: &UnixReady)
{
    if events.is_error() {
        debug!("SSL TcpStream err event {:?}, cli {}", events, td.session_id);
        td.end_whole_session_error(SessionError::ClientStream);
        return;
    }

    // read_open, write_open refer to the bidi BufferedTunnel's current
    // stream. Even if we are using a separate uploader, read_open can (and
    // mostly will) be true: it's referring to the actual TLS stream, rather
    // than an app-level concept.
    let (read_open, write_open) = td.cli_pair.bidi_rw_is_open();
    if events.is_writable() {
        if td.cli_pair.bidi_read_wants_writable() && read_open
         //  && td.cli_pair.bidi_is_active_uploader HACK ok to just read anyways
        {
            td.cli_read_cov_write(rereg_queuer, events.is_hup());
        }
        if write_open {
            td.cov_read_cli_write(rereg_queuer, false);
        } else { // an earlier shutdown() on cli blocked; continue the shut
            if td.cli_pair.bidi_clean_shutdown() == ShutStat::Error {
                td.end_whole_session_error(SessionError::ClientStream);
            }
        }
    }
    if events.is_readable() {
        if td.cli_pair.bidi_write_wants_readable() {
            if write_open {
                td.cov_read_cli_write(rereg_queuer, false);
            } else { // an earlier cli shutdown() blocked; continue the shut
                if td.cli_pair.bidi_clean_shutdown() == ShutStat::Error {
                    td.end_whole_session_error(SessionError::ClientStream);
                }
            }
        }
        if read_open // && td.cli_pair.bidi_is_active_uploader HACK
        {
            td.cli_read_cov_write(rereg_queuer, events.is_hup());
        }
    }
    if events.is_hup() {
        td.handle_cli_bidi_hup();
    }
}

impl ClientSSLDriver
{
    pub fn new() -> ClientSSLDriver
    {
        ClientSSLDriver {
            tok2sess: TokenMap::with_initial_capacity(4096),
            sessions_to_drop: VecDeque::new(),
            rereg_queuer: ReregQueuer::new(),
            session_timeouts: VecDeque::new(),
            stream_timeouts: VecDeque::new(),
        }
    }
}
impl ClientDriver for ClientSSLDriver
{
    // Called on read/write/hup events from the (forged) TCP socket underlying
    // the cobbled-together overt flow SSL object.
    // The is_readable event is data arriving in the client's overt TLS session.
    // We should SSL_read() that data and forward it to the Squid socket.
    // See CovertTCPDriver::process_event() for the other direction.
    fn process_event(&mut self, token: &Token, events: UnixReady)
    {
        let (stream_gone, session_done, session_id,
             session_cli_count, maybe_drop_tok) =
        {
            let ref mut td = {
                if let Some(td_rc) = self.tok2sess.get_mut(token) { //TODO if this is get() rather than get_mut() can we clean this fn up?
                    td_rc.borrow_mut()
                } else {
                    warn!("SSL ev loop fired for {:?}; not in tokmap.", token);
                    return;
                }
            };
            process_ssl_events(&mut self.rereg_queuer, td, &events);
            let stream_gone = !td.cli_pair.bidi_stream_is_some();
            let maybe_drop_tok = if stream_gone { td.cli_pair.take_bidi_tok() }
                                 else           { None };
            (stream_gone, td.both_half_closed(), td.session_id,
             td.cli_pair.stream_count(), maybe_drop_tok)
        };
        if stream_gone {
            if let Some(tok) = maybe_drop_tok {
                self.tok2sess.remove(tok);
            }
            if !session_done {
                self.session_timeouts.push_back(
                    SchedSessionTimeout {
                        drop_time: precise_time_ns() + SESSION_TIMEOUT_NS,
                        id: session_id,
                        stream_count: session_cli_count });
            }
        }
        if session_done { self.sessions_to_drop.push_back(session_id); }
    }

    fn check_sessions_progress(&mut self,
        id2sess: &HashMap<SessionId, Rc<RefCell<TapdanceSession>>>)
    {
        let ref mut sched = &mut self.session_timeouts;
        let ref mut drop_queue = &mut self.sessions_to_drop;

        let right_now = precise_time_ns();
        // !sched.is_empty(): condition for next two unwraps
        while !sched.is_empty() && sched.front().unwrap().drop_time <= right_now
        {
            // unwrap relies on !sched.is_empty()
            let maybe_drop = sched.pop_front().unwrap();
            if let Some(td_rc) = id2sess.get(&maybe_drop.id) {
                let ref mut td = td_rc.borrow_mut();
                let (orig_r, orig_w) = maybe_drop.stream_count;
                let (cur_r, cur_w) = td.cli_pair.stream_count();
                if !(cur_r > orig_r || cur_w > orig_w) {
                    td.end_whole_session_error(SessionError::ClientTimeout);
                    drop_queue.push_back(td.session_id);
                }
            }
        }
    }
    fn check_streams_progress(&mut self,
        id2sess: &HashMap<SessionId, Rc<RefCell<TapdanceSession>>>)
    {
        let ref mut sched = &mut self.stream_timeouts;
        let ref mut drop_queue = &mut self.sessions_to_drop;

        let right_now = precise_time_ns();
        // !sched.is_empty(): condition for next two unwraps
        while !sched.is_empty() && sched.front().unwrap().drop_time <= right_now
        {
            // unwrap relies on !sched.is_empty()
            let maybe_drop = sched.pop_front().unwrap();
            if let Some(td_rc) = id2sess.get(&maybe_drop.id) {
                let ref mut td = td_rc.borrow_mut();
                let (orig_r, orig_w) = maybe_drop.stream_count;
                let (cur_r, cur_w) = td.cli_pair.stream_count();
                if !(cur_r > orig_r || cur_w > orig_w) {
                    td.end_whole_session_error(SessionError::ClientTimeout);
                    drop_queue.push_back(td.session_id);
                }
            }
        }
    }

    fn rereg_queuer(&mut self) -> &mut ReregQueuer
    {
        &mut self.rereg_queuer
    }
}

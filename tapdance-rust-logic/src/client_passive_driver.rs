use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use time::precise_time_ns;

use mio::Token;
use mio::unix::UnixReady;

use client_driver::{ClientDriver, SchedSessionTimeout};
use client_ssl_driver::SESSION_TIMEOUT_NS;
use rereg_queuer::ReregQueuer;
use session_error::SessionError;
use session_id::SessionId;
use tapdance_session::TapdanceSession;
use token_map::TokenMap;

pub struct ClientPassiveDriver
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
        td.end_whole_session_error(SessionError::ClientStream);
        return;
    }
    if events.is_readable() {
        td.cli_read_cov_write(rereg_queuer, events.is_hup());
    }
    if events.is_hup() {
        td.handle_cli_uploader_hup();
    }
}

impl ClientPassiveDriver
{
    pub fn new() -> ClientPassiveDriver
    {
        ClientPassiveDriver {
            tok2sess: TokenMap::with_initial_capacity(4096),
            sessions_to_drop: VecDeque::new(),
            rereg_queuer: ReregQueuer::new(),
            session_timeouts: VecDeque::new(),
            stream_timeouts: VecDeque::new(),
        }
    }
}

impl ClientDriver for ClientPassiveDriver
{
    // Called on read/hup/err events from EventedSSLEavesdroppers.
    // This driver takes over the cli->cov direction from ClientSSLDriver when
    // the passive eavesdropped stream is the active uploader.
    // See CovertTCPDriver::process_event() for the other direction.
    fn process_event(&mut self, token: &Token, events: UnixReady)
    {
        let (stream_gone, session_done, session_id,
             session_cli_count, maybe_drop_tok) =
        {
            let ref mut td = {
                if let Some(td_rc) = self.tok2sess.get_mut(token) {
                    td_rc.borrow_mut()
                } else {
                    warn!("Passive eloop fired for {:?}; not in tokmap.",token);
                    return;
                }
            };
            process_ssl_events(&mut self.rereg_queuer, td, &events);
            let stream_gone = !td.cli_pair.uploader_is_some();
            let maybe_drop_tok = if stream_gone { td.cli_pair.take_upl_tok() }
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

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use mio::Token;
use mio::unix::UnixReady;

use rereg_queuer::ReregQueuer;
use session_id::SessionId;
use tapdance_session::TapdanceSession;

pub trait ClientDriver
{
    fn rereg_queuer(&mut self) -> &mut ReregQueuer;

    fn check_sessions_progress(&mut self,
        id2sess: &HashMap<SessionId, Rc<RefCell<TapdanceSession>>>);
    fn check_streams_progress(&mut self,
        id2sess: &HashMap<SessionId, Rc<RefCell<TapdanceSession>>>);

    fn process_event(&mut self, token: &Token, events: UnixReady);
}

pub struct SchedSessionTimeout
{
    // Nanoseconds since an unspecified epoch (precise_time_ns()).
    pub drop_time: u64,
    pub id: SessionId,
    // The session's cli tunnel's stream_count()s at the time this event was
    // scheduled. When this event comes up, end the session iff the session's
    // cli still has the same stream_count()s as this recorded value.
    // (Upload-only's count, bidi's count).
    pub stream_count: (usize, usize),
}

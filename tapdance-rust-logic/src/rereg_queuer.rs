use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use mio::{Poll, PollOpt};

use session_id::SessionId;
use tapdance_session::TapdanceSession;
use util;

pub struct ReregQueuer
{
    reregs_cli: VecDeque<SessionId>,
    reregs_cov: VecDeque<SessionId>,
}
impl ReregQueuer
{
    pub fn new() -> ReregQueuer
    {
        ReregQueuer { reregs_cli: VecDeque::new(),
                      reregs_cov: VecDeque::new(), }
    }
    pub fn rereg_cli(&mut self, session_id: &SessionId)
    {
        self.reregs_cli.push_back(*session_id);
    }
    pub fn rereg_cov_tcp(&mut self, session_id: &SessionId)
    {
        self.reregs_cov.push_back(*session_id);
    }
    pub fn do_cli_reregs(
        &mut self, bidi_poll: &Poll, upl_poll: &Poll,
        id2td: &mut HashMap<SessionId, Rc<RefCell<TapdanceSession>>>)
    {
        for session_id in self.reregs_cli.drain(..) {
            if let Some(td_rc) = id2td.get(&session_id) {
                let ref td = td_rc.borrow();
                td.cli_pair.do_rereg(bidi_poll, upl_poll);
            }
        }
    }
    pub fn do_cov_reregs(
        &mut self, cov_poll: &Poll,
        id2td: &mut HashMap<SessionId, Rc<RefCell<TapdanceSession>>>)
    {
        for session_id in self.reregs_cov.drain(..) {
            if let Some(td_rc) = id2td.get(&session_id) {
                let ref mut td = td_rc.borrow_mut();
                if let Some(cov_tok) = td.cov.peek_tok() {
                    td.cov.reregister(cov_poll, cov_tok,
                                      util::all_unix_events(), PollOpt::edge())
                          .unwrap_or_else(|e|{warn!("cov rereg err: {}", e)});
                } else {
                    warn!("Couldn't rereg cov for {}; no tok!", td.session_id);
                }
            }
        }
    }
}

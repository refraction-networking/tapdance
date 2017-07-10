use std::io;

use lazycell::LazyCell;
use mio::{Ready, Poll, PollOpt, Registration, SetReadiness, Token};
use mio::unix::UnixReady;

pub struct EventHook
{
    mio_reg: LazyCell<Registration>,
    mio_notifier: LazyCell<SetReadiness>,
    became_readable_before_reg: LazyCell<bool>,
}
impl EventHook
{
    pub fn new() -> EventHook
    {
        EventHook { mio_reg: LazyCell::new(),
                    mio_notifier: LazyCell::new(),
                    became_readable_before_reg: LazyCell::new() }
    }
    pub fn notify_readable(&self)
    {
        if let Some(ref notifier) = self.mio_notifier.borrow() {
            if let Err(e) = notifier.set_readiness(notifier.readiness() |
                                                   Ready::readable())
            {
                warn!("EventHook couldn't set readable: {:?}", e);
            }
        } else {
            if let Err(e) = self.became_readable_before_reg.fill(true) {
                warn!("couldn't fill became_readable_before_reg: {:?}", e);
            }
        }
    }
    pub fn notify_hup(&self)
    {
        if let Some(ref notifier) = self.mio_notifier.borrow() {
            if let Err(e) = notifier.set_readiness(notifier.readiness() |
                                                   UnixReady::hup())
            {
                warn!("EventHook couldn't set hup event: {:?}", e);
            }
        }
    }
    pub fn notify_error(&self)
    {
        if let Some(ref notifier) = self.mio_notifier.borrow() {
            if let Err(e) = notifier.set_readiness(notifier.readiness() |
                                                   UnixReady::error())
            {
                warn!("EventHook couldn't set error event: {:?}", e);
            }
        }
    }
    // TODO there is no dropped(), maybe it was only in that proposal
//     pub fn notify_dropped(&self)
//     {
//         if let Some(ref notifier) = self.mio_notifier.borrow() {
//             let _ = notifier.set_readiness(Ready::dropped());
//         }
//     }
}
impl ::mio::Evented for EventHook
{
    fn register(&self, poll: &Poll, token: Token, interest: Ready,
                opts: PollOpt) -> io::Result<()>
    {
        if self.mio_reg.filled() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                                      "already registered"));
        }
        let (reg, notifier) = Registration::new2();
        if let Err(e) = poll.register(&reg, token, interest, opts) {
            warn!("EventHook couldn't register: {:?}", e);
            return Err(e);
        }
        if let Err(e) = self.mio_reg.fill(reg) {
            warn!("couldn't fill mio_reg: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                                      "couldn't fill mio_reg"));
        }
        if let Err(e) = self.mio_notifier.fill(notifier) {
            warn!("couldn't fill mio_notifier: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                                      "couldn't fill mio_notifier"));
        }

        if let Some(start_readable) = self.became_readable_before_reg.borrow() {
            if *start_readable {
                self.notify_readable();
            }
        }

        Ok(())
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready,
                  opts: PollOpt) -> io::Result<()>
    {
        if let Some(ref mio_reg) = self.mio_reg.borrow() {
            // TODO was update but that's deprecated. Is rereg() right here?
            mio_reg.reregister(poll, token, interest, opts)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "not registered"))
        }
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()>
    {
        if let Some(ref mio_reg) = self.mio_reg.borrow() {
            mio_reg.deregister(poll)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "not registered"))
        }
    }
}

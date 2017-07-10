use mio::{Poll, PollOpt, Ready, Token};
use std::io;
use std::io::{Write,Read};

use stream_traits::{BufferableSender, StreamReceiver,
                    RawWriteStat, ReadStat, ShutStat};

// TODO only supposed to be visible to BufferedTCP.
pub struct BufferableTCP
{
    tcp: ::mio::tcp::TcpStream,
    writes_shut_down: bool,
}
impl BufferableTCP
{
    pub fn new(tcp: ::mio::tcp::TcpStream) -> BufferableTCP
    {
        BufferableTCP { tcp: tcp, writes_shut_down: false }
    }
}
impl BufferableSender for BufferableTCP
{
    fn send(&mut self, data: &[u8]) -> RawWriteStat
    {
        match self.tcp.write(data) {
            Ok(n) => RawWriteStat::Sent(n),
            // We translate Err to Sent(0) to handle the case where there wasn't
            // a real error, rather we just tried to send on a still-opening
            // socket. The driver handles real errors, when it sees an is_error.
            Err(..) => RawWriteStat::Sent(0)
        }
    }
    fn graceful_shutdown(&mut self) -> ShutStat
    {
        if self.writes_shut_down {
            ShutStat::InProgress
        } else {
            if self.tcp.shutdown(::mio::tcp::Shutdown::Write).is_ok() {
                self.writes_shut_down = true;
                ShutStat::InProgress
            } else {
                ShutStat::Error
            }
        }
    }
    fn read_wants_writable(&self) -> bool {false}
    fn write_wants_readable(&self) -> bool {false}
}
impl StreamReceiver for BufferableTCP
{
    fn read(&mut self, data: &mut [u8]) -> ReadStat
    {
        match self.tcp.read(data) {
            Ok(n) => ReadStat::GotData(n),
            Err(..) => ReadStat::WouldBlock
            // Can NOT be CleanShutdown (or Error), or else a close will be
            // reported immediately after the connection is opened.
        }
    }
}
impl ::mio::Evented for BufferableTCP
{
    fn register(&self, poll: &Poll, token: Token, interest: Ready,
                opts: PollOpt) -> io::Result<()>
    {
        self.tcp.register(poll, token, interest, opts)
    }
    fn reregister(&self, poll: &Poll, token: Token, interest: Ready,
                  opts: PollOpt) -> io::Result<()>
    {
        self.tcp.reregister(poll, token, interest, opts)
    }
    fn deregister(&self, poll: &Poll) -> io::Result<()>
    {
        self.tcp.deregister(poll)
    }
}


pub enum RawWriteStat { Sent(usize), WouldBlock, Error }

#[derive(PartialEq)]
pub enum WriteStat { Complete, Buffered, Error }

#[derive(PartialEq)]
pub enum ShutStat { Complete, InProgress, WouldBlock, Error }

#[derive(PartialEq)]
pub enum ReadStat { GotData(usize), WouldBlock, CleanShutdown, Error }

#[derive(PartialEq)]
pub enum BufStat { Empty, Nonempty, Error }

pub trait BufferableSender
{
    fn send(&mut self, data: &[u8]) -> RawWriteStat;
    fn graceful_shutdown(&mut self) -> ShutStat;
    fn read_wants_writable(&self) -> bool;
    fn write_wants_readable(&self) -> bool;
}

pub trait StreamReceiver
{
    fn read(&mut self, buf: &mut [u8]) -> ReadStat;
}

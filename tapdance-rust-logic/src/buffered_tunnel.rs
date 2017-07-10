use mio::{Evented, Poll, PollOpt, Ready, Token};
use mio::unix::UnixReady;
use std::collections::VecDeque;
use std::io;
use std::io::{Error, ErrorKind};

use stream_traits::{BufferableSender, StreamReceiver,
                    BufStat, RawWriteStat, ReadStat, ShutStat, WriteStat};
use token_map::UniqTok;

const MAX_WRITE_SIZE: usize = 16*1024;

// Wraps a buffer around a stream. For when we want a single logical stream to
// persist across a series of actual streams, with writes being buffered when
// in-between streams (in addition to when the stream is WOULDBLOCKing).
pub struct BufferedTunnel<S>
{
    buf: VecDeque<u8>,
    stream: Option<S>,
    writes_open: bool,
    reads_open: bool,
    half_close_pending: bool, // referring to overall session
    half_closed: bool,
    // How many streams this tunnel has gone through, including the current one.
    // Starts at 0, when the object was just created and stream is None.
    stream_count: usize,
    token: Option<UniqTok>,
}

impl<S: BufferableSender + StreamReceiver + Evented> BufferedTunnel<S>
{
    pub fn new() -> BufferedTunnel<S>
    {
        BufferedTunnel { buf: VecDeque::new(),
                         stream: None,
                         writes_open: false,
                         reads_open: false,
                         half_close_pending: false,
                         half_closed: false,
                         stream_count: 0,
                         token: None }
    }

    pub fn buf_is_empty(&self) -> bool { self.buf.is_empty() }

    // Flush the send buffer as much as possible. THIS FUNCTION CAN INTRODUCE A
    // STALL! That is, if the other side's reads were previously paused (to stop
    // filling up this send buffer), and this call empties the send buffer, then
    // you now have neither writeable events on the sender nor readable events
    // on the other stream to get the reads flowing again. In that case, you
    // must manually rereg the reader. The x_read_y_write() functions in
    // TapDanceSession already have that rereg logic correctly in place. Any
    // other usage without those reregs risks a stall, and therefore should only
    // come when the session is already closing down anyways.
    //
    // Returns false if, after this call, there is still data in the buffer.
    pub fn drain_send_buf(&mut self) -> BufStat
    {
        if self.buf.is_empty() {
            return BufStat::Empty;
        }
        let mut do_half_close = false;
        let res = {
        if let Some(ref mut s) = self.stream {
            while !self.buf.is_empty() {
                let mut spliced_vec: Vec<u8> = Vec::new();
                let bytes_written = {
                    // VecDeque can give you its data as two separate chunks if
                    // the underlying ring buffer has wrapped around.
                    let buf_slice = {
                        let (a, b) = self.buf.as_slices();
                        if b.len() != 0 {
                            spliced_vec.reserve(a.len() + b.len());
                            spliced_vec.extend_from_slice(a);
                            spliced_vec.extend_from_slice(b);
                            &spliced_vec[..]
                        }
                        else { a }
                    };
                    let chunk_len = if buf_slice.len() > MAX_WRITE_SIZE
                                    {MAX_WRITE_SIZE} else {buf_slice.len()};
                    match s.send(&buf_slice[0..chunk_len]) {
                        RawWriteStat::Sent(n) => n,
                        RawWriteStat::WouldBlock => 0,
                        RawWriteStat::Error => {return BufStat::Error;}
                    }
                };
                if bytes_written > 0 {
                    self.buf.drain(0..bytes_written);
                } else {
                    break;
                }
            }
            if self.buf.is_empty() {
                // "Previously non-empty buffer has been emptied"
                //
                // NOTE: this spot has been very carefully chosen for where to
                // effect the pending half-close on the still-open stream.
                // We effect it by calling a clean_shutdown()... but that calls
                // drain_send_buf()! We avoid infinite recursion because we know
                // the call to drain_send_buf() will immediately return Empty
                // (because of the 'if' we're inside here).
                //
                // At the same time, we do need to be sure that the pending
                // half-close actually causes the stream to close once the
                // buffer empties. This place does it: we just observed an empty
                // buffer, and yet at the start of the function it was nonempty.
                if self.half_close_pending {
                    do_half_close = true;
                }
                BufStat::Empty
            } else {
                BufStat::Nonempty
            }
        } else { BufStat::Nonempty }};
        if do_half_close {
            self.half_close(); // calls clean_shutdown()+handles result
        }
        return res;
    }

    pub fn write(&mut self, data: &[u8]) -> WriteStat
    {
        if self.half_close_pending {
            error!("Tried write() while half_close_pending!");
            return WriteStat::Error;
        }
        match self.drain_send_buf() {
            BufStat::Empty          => {},
            BufStat::Nonempty       => { self.buf.extend(data);
                                         return WriteStat::Buffered; },
            BufStat::Error          => { return WriteStat::Error; }
        }
        if let Some(ref mut s) = self.stream {
            let send_len = if data.len() > MAX_WRITE_SIZE { MAX_WRITE_SIZE }
                           else                           { data.len() };
            let ret_status = match s.send(&data[..send_len]) {
                RawWriteStat::Sent(n) => {
                    if n != data.len() { self.buf.extend(&data[n..]); }
                    if n == data.len() { WriteStat::Complete }
                    else               { WriteStat::Buffered }
                },
                RawWriteStat::WouldBlock => { self.buf.extend(data);
                                              WriteStat::Buffered },
                RawWriteStat::Error => WriteStat::Error
            };
            return ret_status;
        } else {
            self.buf.extend(data);
            return WriteStat::Buffered;
        }
    }

    // Like write(), but if there is data in the buffer, don't attempt to flush,
    // just enqueue. Useful if you don't have a ReregQueuer: this function will
    // not cause a stall, so you don't need X_read_Y_write() around as backup.
    pub fn write_no_flush(&mut self, data: &[u8]) -> WriteStat
    {
        if self.half_close_pending {
            error!("Tried write_no_flush() while half_close_pending!");
            return WriteStat::Error;
        }
        if !self.buf.is_empty() {
            self.buf.extend(data);
            WriteStat::Buffered
        } else {
            if let Some(ref mut s) = self.stream {
                let send_len = if data.len() > MAX_WRITE_SIZE { MAX_WRITE_SIZE }
                           else                               { data.len() };
                match s.send(&data[..send_len]) {
                    RawWriteStat::Sent(n) => {
                        if n != data.len() { self.buf.extend(&data[n..]); }
                        if n == data.len() { WriteStat::Complete }
                        else               { WriteStat::Buffered }
                    },
                    RawWriteStat::WouldBlock => { self.buf.extend(data);
                                                  WriteStat::Buffered },
                    RawWriteStat::Error => WriteStat::Error
                }
            } else {
                self.buf.extend(data);
                WriteStat::Buffered
            }
        }
    }

    // Writes directly to the stream, *even if there is data in the buffer!*
    // You had better be absolutely sure you know exactly what's going on when
    // you use this, or you are going to reorder data.
    // Returns either Complete or Error; DOES NOT BUFFER!
    // NOTE: this function treats ANY non-success result from stream.send() as
    //       an error, including WOULDBLOCKs. Should be ok since we only call at
    //       the start of a TLS stream.
    pub fn write_skipping_buffer(&mut self, data: &[u8]) -> WriteStat
    {
        if self.half_close_pending {
            error!("Tried write_skipping_buffer() while half_close_pending!");
            return WriteStat::Error;
        }
        if data.len() > MAX_WRITE_SIZE {
            error!("too much data for write_skipping_buffer() : {} bytes",
                   data.len());
            return WriteStat::Error;
        }
        if let Some(ref mut s) = self.stream {
            match s.send(data) {
                RawWriteStat::Sent(n) => {
                    if n == data.len() {
                        WriteStat::Complete
                    } else {
                        error!("SSL wrote only part of our data!");
                        WriteStat::Error
                    }
                },
                RawWriteStat::WouldBlock => {
                    error!("write_skipping_buffer WouldBlock!");
                    WriteStat::Error
                },
                RawWriteStat::Error => WriteStat::Error
            }
        }
        else { WriteStat::Error }
    }

    // Try a clean shutdown of the tunnel's current stream.
    // If "InProgress", call it again whenever the stream receives any event.
    // If "Complete", the underlying stream object has been set to None.
    // Any data that the BufferedTunnel already had buffered when this is called
    // will be written before the actual shutdown is initiated.
    pub fn clean_shutdown(&mut self) -> ShutStat
    {
        self.writes_open = false;
        let result =
        if !self.stream.is_some() {
            ShutStat::Complete
        } else {
            match self.drain_send_buf() {
                BufStat::Nonempty => ShutStat::WouldBlock,
                BufStat::Error    => ShutStat::Error,
                BufStat::Empty    => {
                    if let Some(ref mut s) = self.stream {
                        let raw_res = s.graceful_shutdown();
                        if raw_res == ShutStat::InProgress && !self.reads_open {
                            ShutStat::Complete
                        }
                        else { raw_res }
                    }
                    else { ShutStat::Complete }
                }
            }
        };

        if result == ShutStat::Complete {
            self.stream = None;
        }
        if self.half_close_pending &&
           (result == ShutStat::Complete || result == ShutStat::Error)
        {
            self.half_closed = true;
        }
        result
    }

    pub fn unclean_shutdown(&mut self)
    {
        self.writes_open = false;
        self.reads_open = false;
        self.stream = None;
        if self.half_close_pending {
            self.half_closed = true;
        }
    }

    // A logical, session-level half-close. Once this function is called, the
    // BufferedTunnel object will accept no more writes (even if its underlying
    // stream T is replaced with a new one).
    //
    // When doing this to the client, make sure to send a shutdown proto first!
    pub fn half_close(&mut self)
    {
        self.half_close_pending = true;
        match self.clean_shutdown()
        {
            ShutStat::Complete => {self.half_closed = true},
            ShutStat::Error => {self.half_closed = true},
            _ => {}
        }
    }

    pub fn stream_is_some(&self) -> bool { self.stream.is_some() }

    // Returns whether the (read, write) direction is currently operational.
    // (Maybe blocked, but definitely there and capable of progress).
    // (false, false) DOES NOT imply that the underlying stream is None: there
    // can be a clean shutdown process resolving. Basically, if either of these
    // are false, it's probably a good idea to try a clean_shutdown().
    //
    // It's necessary to track these separately in case it was we the station,
    // and not the remote host, who initiated a clean_shutdown: in that case,
    // reads_open would remain true until the remote host has responded to the
    // shutdown. (At the same time, writes_open==false reminds us we're closing)
    pub fn rw_is_open(&self) -> (bool, bool)
    {
        (self.reads_open, self.writes_open)
    }
    
    pub fn half_close_pending(&self) -> bool { self.half_close_pending }
    pub fn half_closed(&self) -> bool { self.half_closed }
    pub fn stream_count(&self) -> usize { self.stream_count }

    // Inform the struct that its underlying stream is closed to reads.
    // (Realizing that writes are closed is part of [un]clean_shutdown()).
    pub fn set_read_closed(&mut self) { self.reads_open = false; }

    pub fn set_stream(&mut self, stream: S)
    {
        self.stream = Some(stream);
        self.writes_open = true;
        self.reads_open = true;
        self.stream_count += 1;
    }

    pub fn read_wants_writable(&self) -> bool
    {
        if let Some(ref s) = self.stream { s.read_wants_writable() }
        else                             { false }
    }
    pub fn write_wants_readable(&self) -> bool
    {
        if let Some(ref s) = self.stream { s.write_wants_readable() }
        else                             { false }
    }

    pub fn register(&self, poll: &Poll, token: Token,
                    interest: UnixReady, opts: PollOpt) -> io::Result<()>
    {
        if let Some(ref s) = self.stream {
            poll.register(s, token, Ready::from(interest), opts)
        } else {
            Err(Error::new(ErrorKind::NotFound,
                "register() attempted on an unset BufferedTunnel!"))
        }
    }
    pub fn reregister(&self, poll: &Poll, token: Token, interest: UnixReady,
                      opts: PollOpt) -> io::Result<()>
    {
        if let Some(ref s) = self.stream {
            poll.reregister(s, token, Ready::from(interest), opts)
        } else {
            Err(Error::new(ErrorKind::NotFound,
                "reregister() attempted on an unset BufferedTunnel!"))
        }
    }
    pub fn deregister(&self, poll: &Poll) -> io::Result<()>
    {
        if let Some(ref s) = self.stream {
            poll.deregister(s)
        } else {
            Err(Error::new(ErrorKind::NotFound,
                "deregister() attempted on an unset BufferedTunnel!"))
        }
    }
    // In case a TapdanceSession's stored token gets stale, dropping the session
    // should not affect another session that has that token for reals. Please
    // follow the policy of only TokenMap::remove()ing a token gotten from a
    // take_tok(), NOT peek(), and NOT a token gotten from a mio event dispatch.
    pub fn peek_tok(&self) -> Option<Token>
    {
        if let Some(ref tok) = self.token { Some(tok.val()) }
        else                              { None }
    }
    pub fn take_tok(&mut self) -> Option<UniqTok>
    {
        self.token.take()
    }
    pub fn set_tok(&mut self, new_token: UniqTok)
    {
        if let Some(ref old) = self.token {
            warn!("A BufferedTunnel is overwriting its UniqTok {:?} with {:?}",
                  old.val(), new_token.val());
        }
        self.token = Some(new_token);
    }
}

impl<S: BufferableSender + StreamReceiver + Evented> StreamReceiver
    for BufferedTunnel<S>
{
    fn read(&mut self, buf: &mut [u8]) -> ReadStat
    {
        let status = {
            if let Some(ref mut s) = self.stream { s.read(buf) }
            else                                 { ReadStat::WouldBlock }
        };
        if status == ReadStat::CleanShutdown {
            self.set_read_closed();
        }
        status
    }
}

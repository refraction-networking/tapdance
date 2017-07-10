use mio::{Poll, PollOpt, Ready, Token};
use mio::tcp::Shutdown;
use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;
use std::io;
use std::io::{Error, ErrorKind};
use std::os::unix::io::FromRawFd;
use std::os::raw::c_void;

use stream_traits::{BufferableSender, StreamReceiver,
                    RawWriteStat, ReadStat, ShutStat};
use c_api;
use flow_tracker::{Flow,WscaleAndMSS};
use session_id::SessionId;

const SSL_ERROR_NONE: i32 = 0;
const SSL_ERROR_ZERO_RETURN: i32 = 6;
const SSL_ERROR_WANT_READ: i32 = 2;
const SSL_ERROR_WANT_WRITE: i32 = 3;
const SSL_ERROR_WANT_CONNECT: i32 = 7;
const SSL_ERROR_WANT_ACCEPT: i32 = 8;
const SSL_ERROR_WANT_X509_LOOKUP: i32 = 4;
const SSL_ERROR_SYSCALL: i32 = 5;
const SSL_ERROR_SSL: i32 = 1;

#[derive(Debug)]
pub enum SSLErr
{
    CleanShutdown, // TLS session is done (cleanly). Like recv() returning 0.
    WouldBlock, // WANT_READ, WANT_WRITE, etc. "Come back again later!"
    SyscallFailed, // errno probably has something further to tell you.
    Other, // SSL_ERROR_SSL: generic crypto error.
    Unknown, // A value that our Rust wrapper doesn't know about.
    ErrorButNoError, // SSL returned a non-good retval, but then SSL_get_error()
                     // said no error. Should NEVER happen.
}

pub struct BufferableSSL
{
    c_ssl: *mut c_void, //TODO make it an Option?
    underlying_sock: Option<::mio::tcp::TcpStream>,
    read_wants_writable: bool,
    write_wants_readable: bool,
    bytes_recvd: usize,
    bytes_sent: usize,
    session_id: SessionId,
}
impl ::mio::Evented for BufferableSSL
{
    fn register(&self, poll: &Poll, token: Token, interest: Ready,
                opts: PollOpt) -> io::Result<()>
    {
        if let Some(ref sock) = self.underlying_sock {
            sock.register(poll, token, interest, opts)
        } else {
            Err(Error::new(ErrorKind::NotFound,
                "register() attempted on an unset BufferableSSL!"))
        }
    }
    fn reregister(&self, poll: &Poll, token: Token, interest: Ready,
                  opts: PollOpt) -> io::Result<()>
    {
        if let Some(ref sock) = self.underlying_sock {
            sock.reregister(poll, token, interest, opts)
        } else {
            Err(Error::new(ErrorKind::NotFound,
                "reregister() attempted on an unset BufferableSSL!"))
        }
    }
    fn deregister(&self, poll: &Poll) -> io::Result<()>
    {
        if let Some(ref sock) = self.underlying_sock {
            sock.deregister(poll)
        } else {
            Err(Error::new(ErrorKind::NotFound,
                "deregister() attempted on an unset BufferableSSL!"))
        }
    }
}
impl BufferableSSL
{
    pub fn new(session_id: SessionId) -> BufferableSSL
    {
        BufferableSSL { c_ssl: 0 as *mut c_void,
                        underlying_sock: None,
                        read_wants_writable: false,
                        write_wants_readable: false,
                        bytes_recvd: 0,
                        bytes_sent:  0,
                        session_id: session_id }
    }

    // Pass all of these as host order.
    pub fn construct_forged_ssl(&mut self,
                                tcp_pkt: &TcpPacket, flow: &Flow,
                                wscale_and_mss: &WscaleAndMSS,
                                tcp_ts: u32, tcp_ts_ecr: u32,
                                master_key: &[u8],
                                client_random: &[u8],
                                server_random: &[u8]) -> bool
    {
        let tcp_payload = tcp_pkt.payload();

        let mut forged_sock: i32 = -1;
        // IP addrs and ports should be net-order. The rest are host-order.
        self.c_ssl = c_api::c_make_forged_tls(
            flow.dst_ip.to_be(), flow.dst_port.to_be(), // local
            flow.src_ip.to_be(), flow.src_port.to_be(), // remote
            // These libpnet getters all return host order. Ignore the "u32be"
            // in their docs; interactions with pnet are purely host order.
            tcp_pkt.get_acknowledgement(), // our sequence number
            tcp_pkt.get_sequence()
                   .wrapping_add(tcp_payload.len() as u32), // our ACK#
            tcp_pkt.get_window(), wscale_and_mss.wscale, wscale_and_mss.mss,
            tcp_ts, tcp_ts_ecr,
            master_key, 0x2fc0, // TODO: take from connection...(htons(0xc02f))
            &client_random, &server_random, tcp_payload,
            &mut forged_sock as *mut i32);
        self.underlying_sock =
            Some(unsafe{::mio::tcp::TcpStream::from_raw_fd(forged_sock)});

        if self.c_ssl == 0 as *mut c_void { false } else { true }
    }
}
impl BufferableSender for BufferableSSL
{
    // Returns number of bytes written or an error status. Error return implies
    // 0 bytes written; OpenSSL does not do partial writes unless you go out of
    // your way to tell it that's ok.
    fn send(&mut self, input: &[u8]) -> RawWriteStat
    {
        self.write_wants_readable = false;
        match c_api::c_SSL_write(self.c_ssl, input) {
            Ok(n) => { self.bytes_sent += n;
                       RawWriteStat::Sent(n) },
            Err(what) => { // what is the output of a SSL_get_error()
                match what {
                    SSL_ERROR_NONE => RawWriteStat::WouldBlock, // HACK err...
                    SSL_ERROR_ZERO_RETURN => RawWriteStat::WouldBlock,
                    SSL_ERROR_WANT_READ => { self.write_wants_readable = true;
                                             RawWriteStat::WouldBlock },
                    SSL_ERROR_WANT_WRITE => RawWriteStat::WouldBlock,
                    SSL_ERROR_WANT_CONNECT => RawWriteStat::WouldBlock,
                    SSL_ERROR_WANT_ACCEPT => RawWriteStat::WouldBlock,
                    SSL_ERROR_WANT_X509_LOOKUP => RawWriteStat::WouldBlock,
                    SSL_ERROR_SYSCALL => RawWriteStat::WouldBlock,// HACK err...
                    SSL_ERROR_SSL => {
                        // We ignore write errors by returning WouldBlock, which
                        // leads to bursts of calls, so don't print.
                         warn!("SSL_write() got ERROR_SSL. Reason:");
                         c_api::c_ugh_ssl_err();
                        // Instead, clear the error queue, like c_ugh_ssl_err().
                        //c_api::c_ERR_clear_error();
                        RawWriteStat::WouldBlock // HACK should be err...
                    },
                    _ => RawWriteStat::WouldBlock // HACK should be err...
                }
            }
        }
    }
    fn graceful_shutdown(&mut self) -> ShutStat
    {
        self.write_wants_readable = false;
        match c_api::c_SSL_shutdown(self.c_ssl) {
            Ok(done) => if done {ShutStat::Complete}
                        else    {ShutStat::InProgress},
            Err(what) => { // what is the output of a SSL_get_error()
                match what {
                    SSL_ERROR_NONE => ShutStat::Complete, // HACK should be err
                    SSL_ERROR_ZERO_RETURN => ShutStat::Complete,
                    SSL_ERROR_WANT_READ => { self.write_wants_readable = true;
                                             ShutStat::WouldBlock },
                    SSL_ERROR_WANT_WRITE => ShutStat::WouldBlock,
                    SSL_ERROR_WANT_CONNECT => ShutStat::WouldBlock,
                    SSL_ERROR_WANT_ACCEPT => ShutStat::WouldBlock,
                    SSL_ERROR_WANT_X509_LOOKUP => ShutStat::WouldBlock,
                    // TODO Ideally, SYSCALL should result in ReadStat::Error.
                    // However, that would require the client to always send
                    // a TLS CloseNotify before TCP shutdown, which currently
                    // does not always happen. Now that we have the app-level
                    // EXPECT_RECONNECT/SESSION_CLOSE, it's safe to ignore.
                    SSL_ERROR_SYSCALL => ShutStat::Complete,
                    SSL_ERROR_SSL => {
                        warn!("SSL_shutdown() got ERROR_SSL. Reason:");
                        c_api::c_ugh_ssl_err();
                        ShutStat::Complete // HACK should be err...
                    },
                    _ => ShutStat::Complete // HACK should be err...
                }
            }
        }
    }
    fn read_wants_writable(&self) -> bool { self.read_wants_writable }
    fn write_wants_readable(&self) -> bool { self.write_wants_readable }
}
impl StreamReceiver for BufferableSSL
{
    fn read(&mut self, output: &mut [u8]) -> ReadStat
    {
        self.read_wants_writable = false;
        match c_api::c_SSL_read(self.c_ssl, output) {
            Ok(n) => { self.bytes_recvd += n;
                       ReadStat::GotData(n) },
            Err(what) => { // what is the output of a SSL_get_error()
                match what {
                    SSL_ERROR_NONE => ReadStat::CleanShutdown, //HACK err...
                    SSL_ERROR_ZERO_RETURN => ReadStat::CleanShutdown,
                    SSL_ERROR_WANT_READ => ReadStat::WouldBlock,
                    SSL_ERROR_WANT_WRITE => { self.read_wants_writable = true;
                                              ReadStat::WouldBlock },
                    SSL_ERROR_WANT_CONNECT => ReadStat::WouldBlock,
                    SSL_ERROR_WANT_ACCEPT => ReadStat::WouldBlock,
                    SSL_ERROR_WANT_X509_LOOKUP => ReadStat::WouldBlock,
                    // TODO Ideally, SYSCALL should result in ReadStat::Error.
                    // However, that would require the client to always send
                    // a TLS CloseNotify before TCP shutdown, which currently
                    // does not always happen. Now that we have the app-level
                    // EXPECT_RECONNECT/SESSION_CLOSE, it's safe to ignore.
                    SSL_ERROR_SYSCALL => ReadStat::CleanShutdown,
                    SSL_ERROR_SSL => {
                        warn!("SSL_read() got ERROR_SSL. Reason:");
                        c_api::c_ugh_ssl_err();
                        ReadStat::CleanShutdown // HACK should be err...
                    },
                    _ => ReadStat::CleanShutdown // HACK should be err...
                }
            }
        }
    }
}
impl Drop for BufferableSSL
{
    fn drop(&mut self)
    {
        c_api::c_SSL_free(self.c_ssl); // no-op if 0
        self.c_ssl = 0 as *mut c_void;
        if let Some(ref sock) = self.underlying_sock {
            let _ = sock.shutdown(Shutdown::Both);
        }
        self.underlying_sock = None;

        info!("delstream {} {} {}", self.session_id,
              self.bytes_sent, self.bytes_recvd);
        self.bytes_sent = 0;
        self.bytes_recvd = 0;
    }
}

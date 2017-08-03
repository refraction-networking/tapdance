use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_void;

use mio::{Ready, Poll, PollOpt, Token};
use pnet::packet::Packet;
use pnet::packet::tcp::{TcpPacket,TcpFlags};

use c_api;
use event_hook::EventHook;
use mem_open_ssl::MemOpenSSL;
use session_id::SessionId;
use stream_traits::{ReadStat, StreamReceiver};
use util;

#[derive(Debug)]
struct TcpChunk
{
    data: Vec<u8>,
    seq_start: u32, // TCP seq# of first byte of 'data'
    is_fin: bool,
}
impl Ord for TcpChunk
{
    fn cmp(&self, other: &TcpChunk) -> Ordering
    {
        // TODO if both start at same sequence, break ties for longer one
        // other.cmp(self) rather than self.cmp(other), to get a min heap.
        let res = other.seq_start.cmp(&self.seq_start);
        if util::tcp_seq_is_wrapped(self.seq_start, other.seq_start)
             { res.reverse() }
        else { res }
    }
}
impl PartialOrd for TcpChunk
{
    fn partial_cmp(&self, other: &TcpChunk) -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}
impl PartialEq for TcpChunk
{
    fn eq(&self, other: &TcpChunk) -> bool
    {
        self.seq_start == other.seq_start && self.data.len() == other.data.len()
    }
}
impl Eq for TcpChunk {}

pub struct EventedSSLEavesdropper
{
    next_seq: u32, // next TCP seq# in the stream
    // Chunks gotten that start after next_seq. Min-heap on 'seq_start' field.
    tcp_buf: BinaryHeap<TcpChunk>,
    mem_ssl: MemOpenSSL,
    mio_hook: EventHook, // internal mio stuff
    // We tell mio this object is readable whenever we feed enough TLS records
    // into OpenSSL that it tells us that SSL_read() is possible. However, that
    // can happen in the middle of event processing. Because we get our events
    // oneshot(), notifying mio during event processing would have no effect.
    // So, we use this field to remember that once a rereg happens, we should
    // notify mio. Only use its getter and setter!
    became_readable_during_processing: RefCell<bool>,
    bytes_recvd: usize, // for stats
    session_id: SessionId, // for stats logging
    in_order_fin_received: bool,
}
impl EventedSSLEavesdropper
{
    pub fn new(session_id: SessionId) -> EventedSSLEavesdropper
    {
        EventedSSLEavesdropper
        {
            next_seq: 0,
            tcp_buf: BinaryHeap::new(),
            mem_ssl: MemOpenSSL::new(),
            mio_hook: EventHook::new(),
            became_readable_during_processing: RefCell::new(false),
            bytes_recvd: 0,
            session_id: session_id,
            in_order_fin_received: false,
        }
    }
    // Pass all of these as host order.
    pub fn construct_eavesdropped_ssl(
        &mut self, tcp_pkt: &TcpPacket, master_key: &[u8],
        client_random: &[u8], server_random: &[u8]) -> bool
    {
        let tcp_payload = tcp_pkt.payload();

        let new_ssl = c_api::c_make_forged_memory_tls(
            master_key, 0x2fc0, // TODO: take from connection...(htons(0xc02f))
            &client_random, &server_random, tcp_payload,
            self.mem_ssl.membio_from_remote(),
            self.mem_ssl.membio_to_remote());
        if new_ssl == 0 as *mut c_void
        {
            false
        }
        else
        {
            self.next_seq = tcp_pkt.get_sequence()
                                   .wrapping_add(tcp_payload.len() as u32);
            self.mem_ssl.set_ssl_ptr(new_ssl);
            true
        }
    }
    // Returns false if FlowTracker should drop this flow.
    pub fn consume_tcp_pkt(&mut self, tcp_pkt: &TcpPacket) -> bool
    {
        // TODO validate checksums? or does process_packet do that?
        let tcp_flags = tcp_pkt.get_flags();
        if (tcp_flags & TcpFlags::RST) != 0
        {
            self.mio_hook.notify_error();
            return false;
        }
        let is_fin = (tcp_flags & TcpFlags::FIN) != 0;
        self.feed_or_buffer(tcp_pkt.payload(), tcp_pkt.get_sequence(),
                            is_fin, false);
        self.feed_inorder_buffered_segments(false);
        if self.in_order_fin_received
        {
            self.mio_hook.notify_hup();
            return false;
        }
        return true;
    }
    // during_event_processing: is the caller in the middle of an event loop?
    // (False when it's just consume_tcp_pkt called from rust_process_packet).
    // Needed because we need to play some tricks if notify_readable() is going
    // to work inside of event processing, but those tricks would cause extra
    // phantom events if played outside of event processing. Phew, this is
    // complicated! (The other option is to stop using oneshot(), but that would
    // cause even more needless events).
    fn mio_notify_readable(&mut self, during_event_processing: bool)
    {
        // OpenSSL has no reliable way to check if you can read without just
        // trying the read. So... just always claim it's readable. This function
        // only gets called when TCP progress is made: not too many WouldBlocks.
        if during_event_processing
        {
            self.set_became_readable_during_processing(true);
        }
        else
        {
            self.mio_hook.notify_readable();
        }
    }
    // An unwrap in feed_inorder_buffered_segments() relies on this fn returning
    // Some iff tcp_buf is nonempty.
    fn peek_front_usefulness(&self) -> Option<TcpSegmentUsefulness>
    {
        if let Some(seg) = self.tcp_buf.peek()
        {
            Some(self.segment_usefulness(seg.seq_start, seg.data.len() as u32))
        }
        else { None }
    }
    // Feed to SSL all segments in tcp_buf that have become in-order in the TCP
    // stream. (And drop those segments from tcp_buf.)
    // during_event_processing: same as in mio_notify_readable().
    fn feed_inorder_buffered_segments(&mut self, during_event_processing: bool)
    {
        while let Some(usefulness) = self.peek_front_usefulness()
        {
            match usefulness {
            TcpSegmentUsefulness::UsefulNow(start_ind) =>
            {
                // unwrap: "peek_front_usefulness returns Some" implies nonempty
                let popped_seg = self.tcp_buf.pop().unwrap();
                let any_progress = self.feed_or_buffer(
                    &popped_seg.data[start_ind..],
                    popped_seg.seq_start.wrapping_add(start_ind as u32),
                    popped_seg.is_fin,
                    during_event_processing);
                if !any_progress
                {
                    // Avoids an infinite loop in case we have a fragment that
                    // is ready now, but the BIO is not accepting any bytes.
                    // (I am SO glad this got caught in the initial unit tests!)
                    break;
                }
            },
            TcpSegmentUsefulness::UsefulLater => break,
            // Do NOT break. Chunks later in the heap may be usable.
            TcpSegmentUsefulness::UsefulNever => {let _ = self.tcp_buf.pop();},
            }
        }
    }
    // slice_seq_start should be the TCP seq# of the first byte of the slice.
    fn add_slice_to_buffer(&mut self, the_slice: &[u8], slice_seq_start: u32,
                           is_fin: bool)
    {
        let mut chunk_vec = Vec::with_capacity(the_slice.len());
        chunk_vec.extend_from_slice(the_slice);
        self.tcp_buf.push(TcpChunk { data: chunk_vec,
                                     seq_start: slice_seq_start,
                                     is_fin: is_fin });
    }

    // Pass the original slice you tried to feed, how many bytes of it were fed,
    // and the seq# of the first byte in the slice. Buffers the rest.
    fn store_fed_scraps(&mut self, slice_fed: &[u8], fed: u32, is_fin: bool,
                        slice_fed_seq_start: u32)
    {
        // TODO I wonder if this will ever happen?
        warn!("OH NO! BIO_write() did not accept all of the data we
               gave it. We aren't handling this case right now.");
        self.add_slice_to_buffer(&slice_fed[fed as usize..],
                                 slice_fed_seq_start.wrapping_add(fed),
                                 is_fin);
    }

    // Feed this chunk to OpenSSL, or buffer it for later. (Or do nothing if it
    // will never be needed).
    // during_event_processing: same as in mio_notify_readable().
    // Returns whether any progress was made, i.e., any bytes accepted by BIO.
    fn feed_or_buffer(&mut self, chunk: &[u8], chunk_seq_start: u32,
                      is_fin: bool, during_event_processing: bool) -> bool
    {
        let usefulness = self.segment_usefulness(chunk_seq_start,
                                                 chunk.len() as u32);
        if let TcpSegmentUsefulness::UsefulNow(buf_ind_start) = usefulness
        {
            let fed =
                self.mem_ssl.feed_data_from_remote(&chunk[buf_ind_start..]);
            self.next_seq = self.next_seq.wrapping_add(fed);
            let attempted_feed_len = chunk[buf_ind_start..].len() as u32;
            if fed < attempted_feed_len
            {
                self.store_fed_scraps(
                    &chunk[buf_ind_start..], fed, is_fin,
                    chunk_seq_start.wrapping_add(buf_ind_start as u32));
            }
            if is_fin
            {
                self.in_order_fin_received = true;
            }
            if fed > 0
            {
                self.mio_notify_readable(during_event_processing);
                return true;
            }
        }
        else if usefulness == TcpSegmentUsefulness::UsefulLater
        {
            self.add_slice_to_buffer(chunk, chunk_seq_start, is_fin);
        }
        // else (do nothing; the data is stale/already recvd).
        return false;
    }
    fn became_readable_during_processing(&self) -> bool
    {
        if let Ok(ref b) = self.became_readable_during_processing.try_borrow()
        {
            b.deref().clone()
        }
        else
        {
            error!("became_readable_during_processing try_borrow() failed!");
            false
        }
    }
    fn set_became_readable_during_processing(&self, new_val: bool)
    {
        if let Ok(ref mut b) =
            self.became_readable_during_processing.try_borrow_mut()
        {
            *b.deref_mut() = new_val;
        }
        else
        {
            error!("became_readable_during_processing try_borrow_mut failed!");
        }
    }
    // Pass the seq# of your segment's first byte, your segment's length, and
    // the seq# that your TCP stream wants next. Returns whether 1) this segment
    // can advance your TCP stream right now, 2) you should buffer it for the
    // future, or 3) you should discard it.
    fn segment_usefulness(&self, seg_seq_start: u32, seg_len: u32)
    -> TcpSegmentUsefulness
    {
        // TODO cleaner TCP seq space arithmetic and comparisons
        if util::tcp_seq_lte(seg_seq_start, self.next_seq) &&
           util::tcp_seq_lt(self.next_seq, seg_seq_start.wrapping_add(seg_len))
        {
            TcpSegmentUsefulness::UsefulNow(
                self.next_seq.wrapping_sub(seg_seq_start) as usize)
        }
        else if util::tcp_seq_lt(self.next_seq, seg_seq_start)
             { TcpSegmentUsefulness::UsefulLater }
        else { TcpSegmentUsefulness::UsefulNever }
    }
}
#[derive(PartialEq)]
enum TcpSegmentUsefulness
{
    UsefulNow(usize), // 0-based index within this segment where the overall
                      // TCP stream's next desired byte is located.
    UsefulLater,
    UsefulNever
}

impl ::mio::Evented for EventedSSLEavesdropper
{
    fn register(&self, poll: &Poll, token: Token, interest: Ready,
                opts: PollOpt) -> io::Result<()>
    {
        self.mio_hook.register(poll, token, interest, opts)
    }
    fn reregister(&self, poll: &Poll, token: Token, interest: Ready,
                  opts: PollOpt) -> io::Result<()>
    {
        let res = self.mio_hook.reregister(poll, token, interest, opts);
        let brdp = self.became_readable_during_processing();
        if brdp
        {
            self.set_became_readable_during_processing(false);
            self.mio_hook.notify_readable();
        }
        res
    }
    fn deregister(&self, poll: &Poll) -> io::Result<()>
    {
        self.mio_hook.deregister(poll)
    }
}

const SSL_ERROR_NONE: i32 = 0;
const SSL_ERROR_ZERO_RETURN: i32 = 6;
const SSL_ERROR_WANT_READ: i32 = 2;
const SSL_ERROR_WANT_WRITE: i32 = 3;
const SSL_ERROR_WANT_CONNECT: i32 = 7;
const SSL_ERROR_WANT_ACCEPT: i32 = 8;
const SSL_ERROR_WANT_X509_LOOKUP: i32 = 4;
const SSL_ERROR_SYSCALL: i32 = 5;
const SSL_ERROR_SSL: i32 = 1;
impl StreamReceiver for EventedSSLEavesdropper
{
    fn read(&mut self, output: &mut [u8]) -> ReadStat
    {
        match self.mem_ssl.ssl_read(output) {
            Ok(n) => {
                self.bytes_recvd += n;
                // If BIO_write() previously WOULDBLOCKed, SSL_read() returning
                // data is the right time to try again.
                self.feed_inorder_buffered_segments(true);
                // TODO TODO if self.in_order_fin_received() END STREAM
                // (putting this off is a HACK: if BIO_write() blocking when a
                // FIN arrives is rare, we're ok.)
                ReadStat::GotData(n) },
            Err(e) => { // e is the output of a SSL_get_error()
                match e {
                SSL_ERROR_NONE => { self.mio_hook.notify_hup();
                                    ReadStat::CleanShutdown }, //HACK err...
                SSL_ERROR_ZERO_RETURN => { self.mio_hook.notify_hup();
                                           ReadStat::CleanShutdown },
                SSL_ERROR_WANT_READ => ReadStat::WouldBlock,
                SSL_ERROR_WANT_WRITE => { error!("eavesdropper WantWrite");
                                          ReadStat::WouldBlock },
                SSL_ERROR_WANT_CONNECT => ReadStat::WouldBlock,
                SSL_ERROR_WANT_ACCEPT => ReadStat::WouldBlock,
                SSL_ERROR_WANT_X509_LOOKUP => ReadStat::WouldBlock,
                // TODO Ideally, SYSCALL should result in ReadStat::Error.
                // However, that would require the client to always send
                // a TLS CloseNotify before TCP shutdown, which currently
                // does not always happen. Now that we have the app-level
                // EXPECT_RECONNECT/SESSION_CLOSE, it's safe to ignore.
                SSL_ERROR_SYSCALL => { self.mio_hook.notify_hup();
                                       // HACK err...
                                       ReadStat::CleanShutdown },
                SSL_ERROR_SSL => {
                    warn!("SSL_read() got ERROR_SSL. Reason:");
                    c_api::c_ugh_ssl_err();
                    self.mio_hook.notify_hup();
                    ReadStat::CleanShutdown // HACK should be err...
                },
                _ => { self.mio_hook.notify_hup();
                       ReadStat::CleanShutdown }} // HACK should be err...
            }
        }
    }
}

impl Drop for EventedSSLEavesdropper
{
    fn drop(&mut self)
    {
        report!("deluploader {} {}", self.session_id, self.bytes_recvd);
        self.bytes_recvd = 0;
        // TODO not needed? there is no dropped...
        // self.mio_hook.notify_dropped();
    }
}











































#[cfg(test)]
mod tests {

use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};

use evented_ssl_eavesdropper::EventedSSLEavesdropper;
use session_id::SessionId;
use stream_traits::{ReadStat, StreamReceiver};

const PLAIN_TCP_HEADER_LEN: usize = 20;

fn fill_tcpkt(buf: &mut [u8], seq_start: u32, payload: &[u8])
{
    let mut pkt_mut1 = MutableTcpPacket::new(buf).unwrap();
    pkt_mut1.set_sequence(seq_start);
    pkt_mut1.set_data_offset(5);
    pkt_mut1.set_payload(payload);
}

//TODO FIN tests

#[test]
fn consume_single_packet()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(6, ssl.mem_ssl.TESTONLY_buflen());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn consume_two_whole_packets()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(6, ssl.mem_ssl.TESTONLY_buflen());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(10, ssl.mem_ssl.TESTONLY_buflen());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5, 6,7,8,9], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn consume_two_misordered_packets()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(0, ssl.mem_ssl.TESTONLY_buflen());
    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(10, ssl.mem_ssl.TESTONLY_buflen());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5, 6,7,8,9], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn consume_read_consume_read()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    let mut out_buf = [0u8 ; 1480];

    ssl.consume_tcp_pkt(&tcp_pkt1);
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }

    ssl.consume_tcp_pkt(&tcp_pkt2);
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([6,7,8,9], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn packet_after_gap_buffered()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    //                                          NOTE: 7, not 6
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(7u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(6, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(6, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(1, ssl.tcp_buf.len());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn tcp_seq_wraparound()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 4294967290u32; // puts a len 6 chunk at very end of seq space

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 4294967290u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 4294967290u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();
    assert_eq!(0, tcp_pkt2.get_sequence()); // yup, it wrapped

    let mut tcp_buf3 = [0u8 ; PLAIN_TCP_HEADER_LEN + 9];
    fill_tcpkt(&mut tcp_buf3, 4294967290u32.wrapping_add(10u32),
               &[10,11,12,13,14,15,16,17,18]);
    let tcp_pkt3 = TcpPacket::new(&tcp_buf3).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(6, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt3);
    assert_eq!(6, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(1, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(19, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18],
                   out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn partial_feed_buffers()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    // Scheduling limits of (2, 0) because there is first the direct attempt to
    // feed, and then there's the one caused by the "cleanup"
    // feed_inorder_buffered_segments() called at the end of consume_tcp_pkt().
    ssl.mem_ssl.TESTONLY_schedule_feed_accepts(&[2, 0]);
    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(2, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(1, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(10, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5, 6,7,8,9], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn ssl_read_tries_to_drain_buffer()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    // Scheduling limits of (2, 0) because there is first the direct attempt to
    // feed, and then there's the one caused by the "cleanup"
    // feed_inorder_buffered_segments() called at the end of consume_tcp_pkt().
    ssl.mem_ssl.TESTONLY_schedule_feed_accepts(&[2, 0]);
    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(2, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(1, ssl.tcp_buf.len());
    // Only scheduling one '0': it's for the "cleanup". The initial chunk
    // consumption makes no feed attempt, since it doesn't contain the next
    // desired seq#.
    ssl.mem_ssl.TESTONLY_schedule_feed_accepts(&[0]);
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(2, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(2, ssl.tcp_buf.len());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0, 1], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }

    // Caused by the feed_inorder_buffered_segments() in ssl.read()
    assert_eq!(8, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());

    let read_res2 = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res2
    {
        assert_eq!([2,3,4,5,6,7,8,9], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn misordered_and_duplicated()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 8675309u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 6];
    fill_tcpkt(&mut tcp_buf1, 8675309u32, &[0,1,2,3,4,5]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf2, 8675309u32.wrapping_add(6u32), &[6,7,8,9]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(0, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(1, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(0, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(2, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(0, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(3, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(10, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5,6,7,8,9], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
}

#[test]
fn little_bits()
{
    let mut ssl = EventedSSLEavesdropper::new(
        SessionId::new(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));
    ssl.next_seq = 0xc137u32;

    let mut tcp_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 4];
    fill_tcpkt(&mut tcp_buf1, 0xc137u32, &[0,1,2,3]);
    let tcp_pkt1 = TcpPacket::new(&tcp_buf1).unwrap();

    let mut tcp_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 3];
    fill_tcpkt(&mut tcp_buf2, 0xc137u32.wrapping_add(6u32), &[6,7,8]);
    let tcp_pkt2 = TcpPacket::new(&tcp_buf2).unwrap();

    let mut tcp_buf3 = [0u8 ; PLAIN_TCP_HEADER_LEN + 8];
    fill_tcpkt(&mut tcp_buf3,
               0xc137u32.wrapping_add(10u32), &[10,11,12,13,14,15,16,17]);
    let tcp_pkt3 = TcpPacket::new(&tcp_buf3).unwrap();

    let mut tcp_buf4 = [0u8 ; PLAIN_TCP_HEADER_LEN + 5];
    fill_tcpkt(&mut tcp_buf4, 0xc137u32.wrapping_add(19u32), &[19,20,21,22,23]);
    let tcp_pkt4 = TcpPacket::new(&tcp_buf4).unwrap();

    let mut gap_buf1 = [0u8 ; PLAIN_TCP_HEADER_LEN + 3];
    fill_tcpkt(&mut gap_buf1, 0xc137u32.wrapping_add(3u32), &[3,4,5]);
    let tcp_gap1 = TcpPacket::new(&gap_buf1).unwrap();

    let mut gap_buf2 = [0u8 ; PLAIN_TCP_HEADER_LEN + 1];
    fill_tcpkt(&mut gap_buf2, 0xc137u32.wrapping_add(9u32), &[9]);
    let tcp_gap2 = TcpPacket::new(&gap_buf2).unwrap();

    let mut gap_buf3 = [0u8 ; PLAIN_TCP_HEADER_LEN + 2];
    fill_tcpkt(&mut gap_buf3, 0xc137u32.wrapping_add(18u32), &[18,19]);
    let tcp_gap3 = TcpPacket::new(&gap_buf3).unwrap();

    ssl.consume_tcp_pkt(&tcp_pkt1);
    assert_eq!(4, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt2);
    assert_eq!(4, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(1, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt3);
    assert_eq!(4, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(2, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_pkt4);
    assert_eq!(4, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(3, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_gap3);
    assert_eq!(4, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(4, ssl.tcp_buf.len());
    ssl.consume_tcp_pkt(&tcp_gap1);
    assert_eq!(9, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(3, ssl.tcp_buf.len());

    let mut out_buf = [0u8 ; 1480];
    let read_res = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res
    {
        assert_eq!([0,1,2,3,4,5,6,7,8], out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
    assert_eq!(0, ssl.mem_ssl.TESTONLY_buflen());

    ssl.consume_tcp_pkt(&tcp_gap2);
    assert_eq!(15, ssl.mem_ssl.TESTONLY_buflen());
    assert_eq!(0, ssl.tcp_buf.len());

    let read_res2 = ssl.read(&mut out_buf);
    if let ReadStat::GotData(n) = read_res2
    {
        assert_eq!([9,10,11,12,13,14,15,16,17,18,19,20,21,22,23],out_buf[0..n]);
    }
    else
    {
        panic!("SSL_read returned error");
    }
    assert_eq!(0, ssl.mem_ssl.TESTONLY_buflen());
}

} // mod tests

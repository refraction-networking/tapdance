use std::mem;

use protobuf;

use session_error::SessionError;
use signalling::ClientToStation;
use stream_traits::{ReadStat, StreamReceiver};

// This file is the reading half of the station's implementation of the outer
// framing protocol. The outer framing protocol (type+len followed by blob) is
// never supposed to change; it's supposed to be around forever, type+len
// forever 100 years. So, this file should "never" need to change.

// Pass in 1st, 2nd bytes of the TL (big-endian). Returns is_proto, len.
// The len returned might be 0, meaning extended TL.
pub fn parse_typelen(byte1: u8, byte2: u8) -> (bool, usize)
{
    let tl = unsafe { mem::transmute::<[u8;2], i16>([byte2, byte1]) };
    if tl >= 0 {
        (true, tl.clone() as usize)
    } else {
        let len: usize = { if tl == -32768i16 { 32768 as usize }
                           else               { (-tl.clone()) as usize }};
        (false, len)
    }
}

#[cfg(target_endian = "big")]
fn endianness_guard() -> i32
{
    // this function is to prevent you from compiling on a big-endian machine,
    // where the compilation would probably otherwise succeed, but then the
    // program would be wrong, due to little-endian-assuming logic, such as
    // fn parse_typelen() above. if you want to compile on big-endian, you must
    // review all of the station code (rust and C) for endianness issues.
    let mut x = 1;
    let ref mut y = &mut x;
    let z = &mut x;
    y = 2;
    z = 3;
    mem::transmute::<[u8; 4], i32>([x, **y, *z, 123u8])
}

#[derive(PartialEq, Clone, Copy)]
enum FrameMsgState
{
    ParsingTypeLen,
    ParsingExtendedTypeLen,
    // The usizes are the total expected size of the blob being received, as
    // indicated by the (possibly extended) typelen.
    ReceivingData(usize),
    ReceivingProto(usize)
}

pub struct OuterFrameMsgAssembler
{
    buf: Vec<u8>,
    state: FrameMsgState,
}
impl OuterFrameMsgAssembler
{
    pub fn new() -> OuterFrameMsgAssembler
    {
        OuterFrameMsgAssembler { buf: Vec::new(),
                                 state: FrameMsgState::ParsingTypeLen }
    }

    pub fn consume(&mut self, data: &[u8])
    -> (Option<Vec<u8>>, Option<ClientToStation>)
    {
        let mut data_ret: Option<Vec<u8>> = None;
        let mut proto_ret: Option<ClientToStation> = None;
        let mut offset: usize = 0;
        while offset < data.len() {
            let next_state = match self.state {
                FrameMsgState::ParsingTypeLen => {
                    while self.buf.len() < 2 && offset < data.len() {
                        self.buf.push(data[offset]);
                        offset += 1;
                    }
                    if self.buf.len() == 2 {
                        let (is_proto, msg_len) = parse_typelen(self.buf[0],
                                                                self.buf[1]);
                        self.buf.clear();
                        if msg_len == 0 {
                            FrameMsgState::ParsingExtendedTypeLen
                        }
                        else if is_proto {
                            FrameMsgState::ReceivingProto(msg_len)
                        } else {
                            FrameMsgState::ReceivingData(msg_len)
                        }
                    } else {
                        return (None, None);
                    }
                },
                FrameMsgState::ParsingExtendedTypeLen => {
                    while self.buf.len() < 4 && offset < data.len() {
                        self.buf.push(data[offset]);
                        offset += 1;
                    }
                    if self.buf.len() == 4 {
                        let msg_len = {
                            let buf_slice = self.buf.as_slice();
                            let slice_ref = array_ref![buf_slice, 0, 4].clone();
                            unsafe {mem::transmute::<[u8;4], u32>(slice_ref)}
                                    .to_be() as usize
                        };
                        self.buf.clear();
                        FrameMsgState::ReceivingProto(msg_len)
                    }
                    else {
                        return (None, None);
                    }
                },
                FrameMsgState::ReceivingData(n) => {
                    if self.buf.len() + (data.len() - offset) < n {
                        self.buf.extend_from_slice(&data[offset..]);
                        offset = data.len();
                        FrameMsgState::ReceivingData(n)
                    }
                    else if self.buf.len() + (data.len() - offset) == n {
                        self.buf.extend_from_slice(&data[offset..]);
                        offset = data.len();
                        data_ret = Some(self.buf.clone());
                        self.buf.clear();
                        FrameMsgState::ParsingTypeLen
                    } else {
                        error!("consume() called with more data than \
                                recommended! Session now in bad state!");
                        return (None, None);
                    }
                },
                FrameMsgState::ReceivingProto(n) => {
                    if self.buf.len() + (data.len() - offset) < n {
                        self.buf.extend_from_slice(&data[offset..]);
                        offset = data.len();
                        FrameMsgState::ReceivingProto(n)
                    }
                    else if self.buf.len() + (data.len() - offset) == n
                    {
                        self.buf.extend_from_slice(&data[offset..]);
                        offset = data.len();
                        proto_ret = proto_parse(&self.buf.as_slice());
                        self.buf.clear();
                        FrameMsgState::ParsingTypeLen
                    } else {
                        error!("consume() called with more proto-data than \
                                recommended! Session now in bad state!");
                        return (None, None);
                    }
                }
            };
            self.state = next_state;
            if data_ret.is_some() || proto_ret.is_some() {
                return (data_ret, proto_ret);
            }
        }
        return (None, None);
    }

    // Returns true iff expecting the first byte of the TL (which implies a
    // recommended consume size of 2). In that case, the caller will try to do
    // the consumption itself, to skip the fragmentation buffer.
    pub fn is_fresh(&self) -> bool
    {
        self.state == FrameMsgState::ParsingTypeLen && self.buf.is_empty()
    }
    // Call before each consume. It is recommended to feed consume() this much
    // data if possible, and FORBIDDEN to feed it any more!
    pub fn recommended_consume_size(&self) -> usize
    {
        match self.state {
            FrameMsgState::ParsingTypeLen => (2 - self.buf.len()),
            FrameMsgState::ParsingExtendedTypeLen => (4 - self.buf.len()),
            FrameMsgState::ReceivingData(n) => (n - self.buf.len()),
            FrameMsgState::ReceivingProto(n) => (n - self.buf.len())
        }
    }



    // The functions above implement the protobufs/data-message extraction state
    // machine. The functions below do the actual read()s, call the functions
    // above when needed (but do *not* call them if avoidable, as a fast path
    // that avoids some data copying), and return full protobuf/data messages.



    // Entry points to the full OuterFrameMsgAssembler machinery. Perhaps before
    // calling this function, you already read() some bytes. Perhaps you read()
    // into two separate buffers (2 byte TL and then something else). The 1buf,
    // 2bufs variants are for those cases.
    //
    // Consume tl_hdr, then consume buf2, then consume from a read().
    // The return values have the same meaning as those of read_whole_cli_msg().
    fn full_cli_parse_2bufs(&mut self, tl_hdr: &[u8], buf2: &[u8],
                            reader: &mut StreamReceiver)
    -> Result<(bool, usize, Option<Vec<u8>>, Option<ClientToStation>),
              SessionError>
    {
        if tl_hdr.len() > 2 {
            error!("You passed a slice larger than 2 for tl_hdr. You're \
                    probably using full_cli_parse_2bufs() wrong.");
            return Err(SessionError::StationInternal);
        }
        let (_, _) = self.consume(tl_hdr);
        return self.full_cli_parse_1buf(buf2, reader);
    }
    // Consume buf, then consume from a read().
    // The return values have the same meaning as those of read_whole_cli_msg().
    fn full_cli_parse_1buf(&mut self, buf: &[u8], reader: &mut StreamReceiver)
    -> Result<(bool, usize, Option<Vec<u8>>, Option<ClientToStation>),
              SessionError>
    {
        let recmnd_size = self.recommended_consume_size();
        if recmnd_size < buf.len() {
            error!("Already-read buf larger than assembler wants to consume.");
            return Err(SessionError::StationInternal);
        }
        let (maybe_data, maybe_proto) = self.consume(buf);
        if maybe_data.is_some() {
            return Ok((true, 0, maybe_data, None));
        }
        if maybe_proto.is_some() {
            return Ok((true, 0, None, maybe_proto));
        }
        return self.full_cli_parse_no_buf(reader);
    }
    // Consume from a read().
    // The return values have the same meaning as those of read_whole_cli_msg().
    fn full_cli_parse_no_buf(&mut self, reader: &mut StreamReceiver)
    -> Result<(bool, usize, Option<Vec<u8>>, Option<ClientToStation>),
              SessionError>
    {
        let recmnd_read_size = self.recommended_consume_size();
        let mut rbuf = [0; 32*1024];
        let attempt_size = if rbuf.len() < recmnd_read_size {rbuf.len()}
                           else                             {recmnd_read_size};
        let read_size = read_from_stream(reader, &mut rbuf[0..attempt_size]);
        if read_size <= 0 {
            return Ok((false, 0, None, None)); // "reads are blocking"
        }
        let (maybe_data, maybe_proto) = self.consume(&rbuf[0..read_size]);
        if maybe_data.is_some() {
            return Ok((true, 0, maybe_data, None));
        }
        if maybe_proto.is_some() {
            return Ok((true, 0, None, maybe_proto));
        }
        return Ok((true, 0, None, None));
    }

    // Return values are
    // 1) any_bytes_read (i.e. raw from the stream. 0 => shutdown or blocking).
    // 2) num_bytes_recvd_for_complete_data_msg (i.e. the first this many bytes
    //    of data_buf are filled with good data)
    // 3) a data message that was assembled. It's in here rather than written
    //    into data_buf for purely plumbing reasons.
    // 4) maybe_a_proto
    pub fn read_whole_cli_msg(&mut self, data_buf: &mut [u8],
                              reader: &mut StreamReceiver)
    -> Result<(bool, usize, Option<Vec<u8>>, Option<ClientToStation>),
              SessionError>
    {
        // If we're in the middle of a message, have the machinery handle it.
        if !self.is_fresh() {
            return self.full_cli_parse_no_buf(reader);
        }

        // Ok, this is the start of a message, so let's try for the fast path.
        // First try getting the 2-byte TL.
        let mut recvd_tl = [0; 2];
        let tl_bytes_read = read_from_stream(reader, &mut recvd_tl);
        if tl_bytes_read <= 0 {
            return Ok((false, 0, None, None)); // "reads are blocking"
        }
        // Only got 1 of the 2 bytes? Toss it into the machine and we're done.
        if tl_bytes_read == 1 {
            return self.full_cli_parse_1buf(&recvd_tl[0..1], reader);
        }
        let (is_proto, msg_len) = parse_typelen(recvd_tl[0], recvd_tl[1]);
        // Successfully got TL! First, TL==0 is a special case; let the machine
        // handle it. NOTE: from here on, even though we've parsed TL ourselves,
        // the machine needs those 2 bytes if we don't cleanly get the message
        // in this one shot.
        if msg_len == 0 {
            return self.full_cli_parse_1buf(&recvd_tl[0..2], reader);
        }

        // Try to read the blob described by TL.
        let attmpt_size = if data_buf.len() < msg_len { data_buf.len() }
                          else                        { msg_len };
        let bytes_read = read_from_stream(reader,&mut data_buf[0..attmpt_size]);
        if bytes_read <= 0 {
            // the machine will return the "reads are blocking" 'false' for us.
            return self.full_cli_parse_1buf(&recvd_tl[0..2], reader);
        }
        // If we didn't get the whole thing, throw everything we have into the
        // machine. Otherwise, return our nicely gotten thing.
        if bytes_read < msg_len {
            return self.full_cli_parse_2bufs(&recvd_tl[0..2],
                                             &data_buf[0..bytes_read], reader);
        }
        if is_proto {
            let ret_proto =
            match protobuf::parse_from_bytes::<ClientToStation>
                                              (&data_buf[0..bytes_read])
            {
                Ok(p) => Some(p),
                Err(e) => {
                    error!("Parsing a supposed protoblob failed: {:?}", e);
                    return Err(SessionError::ClientProtocol);}
            };
            return Ok((true, 0, None, ret_proto));
        }
        else {
            // Because we read directly into data_buf, we just report how many
            // bytes were read; no copies! Hooray!
            return Ok((true, bytes_read, None, None));
        }
    }
}
// Returns # of bytes read into buf. Error, WouldBlock, Shutdown all return 0.
fn read_from_stream(reader: &mut StreamReceiver, buf: &mut [u8]) -> usize
{
    if let ReadStat::GotData(n) = reader.read(buf) { n }
    else {0}
}

fn proto_parse(raw_bytes: &[u8]) -> Option<ClientToStation>
{
    match protobuf::parse_from_bytes::<ClientToStation>(raw_bytes)
    {
        Ok(p) => Some(p),
        Err(what) => { error!("Parsing what was supposedly a full protobuf \
                                blob failed with: {:?}. Session is bad.", what);
                       None
                     }
    }
}























// TODO get these into their own file

#[cfg(test)]
mod tests {

use std::mem;

use protobuf;
use protobuf::Message;

use protocol_outer_framing::{FrameMsgState,OuterFrameMsgAssembler,
                             parse_typelen};
use signalling::ClientToStation;

fn make_simple_proto(ver: u32, gen: u32, pad_len: usize) -> Vec<u8>
{
    let mut msg = ClientToStation::new();
    msg.set_protocol_version(ver);
    msg.set_decoy_list_generation(gen);
    msg.set_padding({
        let mut padding: Vec<u8> = Vec::with_capacity(pad_len);
        for i in 0..pad_len {
            padding.push((i % 256) as u8);
        }
        padding
    });
    let mut ret_vec: Vec<u8> = Vec::new();
    msg.write_to_vec(&mut ret_vec);
    ret_vec
}

// This test assumes it's running on a little-endian machine. (Which is good,
// because the actual code does, too).
#[test]
fn basic_parse_typelen_test()
{
    let host_order0: i16 = -1;
    let bytes0: [u8; 2] = unsafe { mem::transmute::<i16, [u8;2]>(host_order0) };
    let (is_proto0, len0) = parse_typelen(bytes0[1], bytes0[0]);
    assert!(!is_proto0);
    assert_eq!(1, len0);

    let host_order1: i16 = -50;
    let bytes1: [u8; 2] = unsafe { mem::transmute::<i16, [u8;2]>(host_order1) };
    let (is_proto1, len1) = parse_typelen(bytes1[1], bytes1[0]);
    assert!(!is_proto1);
    assert_eq!(50, len1);

    let host_order2: i16 = -32768;
    let bytes2: [u8; 2] = unsafe { mem::transmute::<i16, [u8;2]>(host_order2) };
    let (is_proto2, len2) = parse_typelen(bytes2[1], bytes2[0]);
    assert!(!is_proto2);
    assert_eq!(32768, len2);

    let host_order3: i16 = 32767;
    let bytes3: [u8; 2] = unsafe { mem::transmute::<i16, [u8;2]>(host_order3) };
    let (is_proto3, len3) = parse_typelen(bytes3[1], bytes3[0]);
    assert!(is_proto3);
    assert_eq!(32767, len3);

    let host_order4: i16 = 1111;
    let bytes4: [u8; 2] = unsafe { mem::transmute::<i16, [u8;2]>(host_order4) };
    let (is_proto4, len4) = parse_typelen(bytes4[1], bytes4[0]);
    assert!(is_proto4);
    assert_eq!(1111, len4);

    let host_order5: i16 = 0;
    let bytes5: [u8; 2] = unsafe { mem::transmute::<i16, [u8;2]>(host_order5) };
    let (is_proto5, len5) = parse_typelen(bytes5[1], bytes5[0]);
    assert!(is_proto5);
    assert_eq!(0, len5);
}

#[test]
fn small_data_msg_all_at_once()
{
    let mut asm = OuterFrameMsgAssembler::new();
    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = -16;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    assert_eq!(16, asm.recommended_consume_size());
    let (the_data, no_proto) = asm.consume(&[111; 16]);
    assert!(!no_proto.is_some());
    assert_eq!([111; 16], the_data.unwrap().as_slice());
}

#[test]
fn small_data_msg_two_chunks()
{
    let mut asm = OuterFrameMsgAssembler::new();
    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = -16;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    assert_eq!(16, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&[55; 9]));
    assert_eq!(7, asm.recommended_consume_size());
    let (the_data, no_proto) = asm.consume(&[55; 7]);
    assert!(!no_proto.is_some());
    assert_eq!([55; 16], the_data.unwrap().as_slice());
}

#[test]
fn small_data_msg_byte_by_byte()
{
    let mut asm = OuterFrameMsgAssembler::new();
    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = -16;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    for i in 0..15
    {
        assert_eq!(16-i, asm.recommended_consume_size());
        assert_eq!((None, None), asm.consume(&[222]));
    }
    assert_eq!(1, asm.recommended_consume_size());
    let (the_data, no_proto) = asm.consume(&[222]);
    assert!(!no_proto.is_some());
    assert_eq!([222; 16], the_data.unwrap().as_slice());
}

#[test]
fn big_data_msg_all_at_once()
{
    let mut asm = OuterFrameMsgAssembler::new();
    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = -32768;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    assert_eq!(32768, asm.recommended_consume_size());
    let (the_data, no_proto) = asm.consume(&[111; 32768]);
    assert!(!no_proto.is_some());
    assert_eq!(32768, the_data.unwrap().as_slice().len());
}

#[test]
fn big_data_msg_two_chunks()
{
    let mut asm = OuterFrameMsgAssembler::new();
    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = -32768;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    assert_eq!(32768, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&[55; 32768/2]));
    assert_eq!(32768/2, asm.recommended_consume_size());
    let (the_data, no_proto) = asm.consume(&[55; 32768/2]);
    assert!(!no_proto.is_some());
    assert_eq!(32768, the_data.unwrap().as_slice().len());
}

#[test]
fn proto_msg_all_at_once()
{
    let mut asm = OuterFrameMsgAssembler::new();
    let proto_vec = make_simple_proto(1234, 5678, 0);

    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = proto_vec.len() as i16;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    assert_eq!(proto_vec.len(), asm.recommended_consume_size());
    let (no_data, maybe_out_proto) = asm.consume(proto_vec.as_slice());
    assert!(!no_data.is_some());
    let out_proto = maybe_out_proto.unwrap();
    assert_eq!(1234, out_proto.get_protocol_version());
    assert_eq!(5678, out_proto.get_decoy_list_generation());
}

#[test]
fn proto_msg_two_chunks()
{
    let mut asm = OuterFrameMsgAssembler::new();
    let proto_vec = make_simple_proto(1234, 5678, 3);

    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());

    let tl_host_order: i16 = proto_vec.len() as i16;
    let tl_bytes: [u8; 2] =
        unsafe { let bytes_host = mem::transmute::<i16, [u8;2]>(tl_host_order);
                 [bytes_host[1], bytes_host[0]]};
    assert_eq!((None, None), asm.consume(&tl_bytes));

    let ref vec_slice = proto_vec.as_slice();

    assert_eq!(proto_vec.len(), asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&vec_slice[0..2]));
    assert_eq!(proto_vec.len()-2, asm.recommended_consume_size());
    let (no_data, maybe_out_proto) = asm.consume(&vec_slice[2..]);
    assert!(!no_data.is_some());
    let out_proto = maybe_out_proto.unwrap();
    assert_eq!(1234, out_proto.get_protocol_version());
    assert_eq!(5678, out_proto.get_decoy_list_generation());
}

#[test]
fn proto_msg_extended_tl()
{
    let mut asm = OuterFrameMsgAssembler::new();
    let proto_vec = make_simple_proto(1234, 5678, 64 * 1024);

    // Or else we aren't testing with a true extended TL!
    assert!(proto_vec.len() > 32 * 1024);

    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&[0, 0]));

    let tl_extended_bytes: [u8; 4] =
        unsafe { let bytes_host = mem::transmute::<u32, [u8;4]>
                                                  (proto_vec.len() as u32);
                 [bytes_host[3], bytes_host[2], bytes_host[1], bytes_host[0]]};
    assert_eq!(4, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&tl_extended_bytes[..]));

    let ref vec_slice = proto_vec.as_slice();
    let mut offset: usize = 0;
    loop {
        let size_to_feed = asm.recommended_consume_size();
        let (_, maybe) = asm.consume(&vec_slice[offset..offset+size_to_feed]);
        offset += size_to_feed;
        if let Some(out_proto) = maybe {
            assert_eq!(1234, out_proto.get_protocol_version());
            assert_eq!(5678, out_proto.get_decoy_list_generation());
            break;
        }
    }
}

#[test]
fn proto_msg_extended_tl_2_extended_tl_chunks()
{
    let mut asm = OuterFrameMsgAssembler::new();
    let proto_vec = make_simple_proto(1234, 5678, 64 * 1024);

    // Or else we aren't testing with a true extended TL!
    assert!(proto_vec.len() > 32 * 1024);

    assert!(asm.is_fresh());
    assert_eq!(2, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&[0, 0]));

    let tl_extended_bytes: [u8; 4] =
        unsafe { let bytes_host = mem::transmute::<u32, [u8;4]>
                                                  (proto_vec.len() as u32);
                 [bytes_host[3], bytes_host[2], bytes_host[1], bytes_host[0]]};
    // Break the extended TL up into 2 reads just to stress things a bit.
    assert_eq!(4, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&tl_extended_bytes[0..2]));
    assert_eq!(2, asm.recommended_consume_size());
    assert_eq!((None, None), asm.consume(&tl_extended_bytes[2..4]));

    let ref vec_slice = proto_vec.as_slice();
    let mut offset: usize = 0;
    loop {
        let size_to_feed = asm.recommended_consume_size();
        let (_, maybe) = asm.consume(&vec_slice[offset..offset+size_to_feed]);
        offset += size_to_feed;
        if let Some(out_proto) = maybe {
            assert_eq!(1234, out_proto.get_protocol_version());
            assert_eq!(5678, out_proto.get_decoy_list_generation());
            break;
        }
    }
}

} // mod tests

use rand::{thread_rng, Rng};
use std::mem;

use protobuf::Message;

use session_error::SessionError;
use signalling::{S2C_Transition, StationToClient};

const TAPDANCE_PROTOCOL_VERSION: u32 = 1;

pub fn make_simple_proto(msg_type: S2C_Transition) -> StationToClient
{
    let mut msg = StationToClient::new();
    msg.set_protocol_version(TAPDANCE_PROTOCOL_VERSION);
    msg.set_state_transition(msg_type);
    msg.set_padding({
        let pad_len = thread_rng().gen_range(1, 200);
        let mut padding: Vec<u8> = Vec::with_capacity(pad_len);
        for i in 0..pad_len {
            padding.push((i % 256) as u8);
        }
        padding
    });
    msg
}

// These next two functions are the writing half of the station's
// implementation of the outer framing protocol. They should never, ever need to
// change! If they do, all clients will have to change as well.
//
// Writes the type+len i16 into the first two bytes of header_target. (The len
// info for the type+len i16 is taken from the data_len argument).
pub fn write_data_tl_hdr(header_target: &mut [u8], data_len: usize)
{
    let net_order_neg_len: i16 =
        if data_len < 32768 {
            (-(data_len as i16)).to_be()
        }
        else if data_len == 32768 { // special case: +32768 would overflow i16
            (-32768i16).to_be()
        }
        else {
            panic!("Attempted to send a data chunk of size {}. Max is 32768.",
                   data_len);
        };
    let len_bytes = unsafe { mem::transmute::<i16, [u8;2]>(net_order_neg_len) };
    header_target[0] = len_bytes[0];
    header_target[1] = len_bytes[1];
}
// Allocates space for a framed protobuf message, with the protobuf itself being
// the given size. Writes the type+len value into the first 2 (or 6) bytes.
// (Returned Vec has capacity for the whole message, but len() only 2 (or 6)).
pub fn empty_proto_frame_with_len(len: usize) -> Vec<u8>
{
    if len <= 32767 {
        let mut frame: Vec<u8> = Vec::with_capacity(2 + len);
        let net_order_len: i16 = (len as i16).to_be();
        let len_bytes = unsafe { mem::transmute::<i16, [u8;2]>(net_order_len) };
        frame.push(len_bytes[0]);
        frame.push(len_bytes[1]);
        frame
    }
    else { // we need "16-bit type+len = 0, real len is next 4 bytes"
        let mut frame: Vec<u8> = Vec::with_capacity(6 + len);
        frame.push(0);
        frame.push(0);
        let net_order_len: u32 = (len as u32).to_be();
        let len_bytes = unsafe { mem::transmute::<u32, [u8;4]>(net_order_len) };
        frame.push(len_bytes[0]);
        frame.push(len_bytes[1]);
        frame.push(len_bytes[2]);
        frame.push(len_bytes[3]);
        frame
    }
}

pub fn make_session_init_msg() -> Vec<u8>
{
    let body = make_simple_proto(S2C_Transition::S2C_SESSION_INIT);
    let mut frame = empty_proto_frame_with_len(body.compute_size() as usize);
    body.write_to_vec(&mut frame)
        .unwrap_or_else(|e|{error!("writing init proto body failed: {}", e);});
    frame
}

pub fn make_confirm_reconnect_msg() -> Vec<u8>
{
    let body = make_simple_proto(S2C_Transition::S2C_CONFIRM_RECONNECT);
    let mut frame = empty_proto_frame_with_len(body.compute_size() as usize);
    body.write_to_vec(&mut frame)
        .unwrap_or_else(|e|{error!("writing recon proto body failed: {}", e);});
    frame
}

pub fn make_session_close_msg() -> Vec<u8>
{
    let body = make_simple_proto(S2C_Transition::S2C_SESSION_CLOSE);
    let mut frame = empty_proto_frame_with_len(body.compute_size() as usize);
    body.write_to_vec(&mut frame)
        .unwrap_or_else(|e|{error!("writing close proto body failed: {}", e);});
    frame
}

pub fn make_err_msg(why: SessionError) -> Vec<u8>
{
    let mut body = make_simple_proto(S2C_Transition::S2C_ERROR);
    body.set_err_reason(why.to_s2c_proto_enum());
    let mut frame = empty_proto_frame_with_len(body.compute_size() as usize);
    body.write_to_vec(&mut frame)
        .unwrap_or_else(|e|{error!("writing 'err' proto body failed: {}", e);});
    frame
}














#[cfg(test)]
mod tests {
use protobuf;
use protobuf::Message;

use protocol_sta2cli;
use signalling::{S2C_Transition, StationToClient};

// Demonstrating that, despite the name, write_to_vec() actually appends to a
// Vec, not overwrites. Leaving this here because it's undocumented.
#[test]
fn proto_write_to_vec_appends()
{
    let mut msg = StationToClient::new();
    msg.set_protocol_version(123);

    let protobuf_size = msg.compute_size() as usize;
    let mut frame =
        protocol_sta2cli::empty_proto_frame_with_len(protobuf_size);
    assert_eq!(2, frame.len());
    msg.write_to_vec(&mut frame);
    assert_eq!(protobuf_size+2, frame.len());
    let out_proto =
    match protobuf::parse_from_bytes::<StationToClient>(&frame.as_slice()[2..])
    {
        Ok(p) => Some(p),
        Err(what) => panic!("didn't get a protobuf back")
    }.unwrap();
    assert_eq!(123, out_proto.get_protocol_version());
}
} // mod tests

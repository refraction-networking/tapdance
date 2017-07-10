extern crate libc;

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use mio::Ready;
use mio::unix::UnixReady;
use pnet::packet::Packet;
use pnet::packet::tcp::{TcpOptionNumbers, TcpPacket};

pub fn all_unix_events() -> UnixReady
{
    UnixReady::from(Ready::readable() | Ready::writable()) |
    UnixReady::hup() | UnixReady::error()
}
pub fn all_but_writable() -> Ready
{
    Ready::from(UnixReady::from(Ready::readable()) 
                | UnixReady::hup() | UnixReady::error())
}
pub fn all_but_readable() -> UnixReady
{
    UnixReady::from(Ready::writable()) | UnixReady::hup() | UnixReady::error()
}
pub fn hup_and_error() -> Ready
{
    Ready::from(UnixReady::hup() | UnixReady::error())
}

// Pass in a host-order IPv4 addr, get a String.
#[inline]
pub fn inet_htoa(ip: u32) -> String {
    format!("{}.{}.{}.{}", (ip >> 24) & 0xff,
                           (ip >> 16) & 0xff,
                           (ip >>  8) & 0xff,
                           (ip)       & 0xff)
}

// Returns host-order u32.
#[inline]
pub fn deser_be_u32_slice(arr: &[u8]) -> u32
{
    if arr.len() != 4 {
        error!("deser_be_u32_slice given bad slice. length: {}", arr.len());
        return 0;
    }

    (arr[0] as u32) << 24 |
    (arr[1] as u32) << 16 |
    (arr[2] as u32) << 8 |
    (arr[3] as u32)
}
#[inline]
pub fn deser_be_u32(arr: &[u8; 4]) -> u32
{
    (arr[0] as u32) << 24 |
    (arr[1] as u32) << 16 |
    (arr[2] as u32) << 8 |
    (arr[3] as u32)
}

// Returns (tcp_ts, tcp_ts_ecr) in host order.
pub fn get_tcp_timestamps(tcp_pkt: &TcpPacket) -> (u32, u32)
{
    match tcp_pkt.get_options_iter()
                 .find(|x| x.get_number() == TcpOptionNumbers::TIMESTAMPS)
    {
        Some(p) => (deser_be_u32_slice(&p.payload()[0..4]),  // timestamp
                    deser_be_u32_slice(&p.payload()[4..8])), // echo reply
        None => (0, 0),
    }
}

// Call on two TCP seq#s from reasonably nearby within the same TCP connection.
// No need for s1 to be earlier in the sequence than s2.
// Returns whether a wraparound happened in between.
pub fn tcp_seq_is_wrapped(s1: u32, s2: u32) -> bool
{
    ((s1 as i64) - (s2 as i64)).abs() > 2147483648
}

// a <= b, guessing about wraparound
pub fn tcp_seq_lte(a: u32, b: u32) -> bool
{
    if a == b { true }
    else {
        let res = a < b;
        if tcp_seq_is_wrapped(a, b) { !res }
        else                        { res }
    }
}
// a < b, guessing about wraparound
pub fn tcp_seq_lt(a: u32, b: u32) -> bool
{
    if a == b { false }
    else {
        let res = a < b;
        if tcp_seq_is_wrapped(a, b) { !res }
        else                        { res }
    }
}

// Returns memory used by this process. Should be equivalent to the RES field of
// top. Units are "kB", which I'm guessing is KiB.
pub fn mem_used_kb() -> u64
{
    let my_pid: i32 = unsafe { libc::getpid() };
    let f = match File::open(format!("/proc/{}/status", my_pid)) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open /proc/{}/status: {:?}", my_pid, e);
            return 0; }
    };
    let buf_f = BufReader::new(f);
    for l in buf_f.lines() {
        if let Ok(line) = l {
            if line.contains("VmRSS") {
                let (_, vmrss_gone) = line.split_at(6);
                let starts_at_number = vmrss_gone.trim_left();
                if let Some(kb_ind) = starts_at_number.find("kB") {
                    let (kb_gone, _) = starts_at_number.split_at(kb_ind);
                    let just_number = kb_gone.trim_right();
                    if let Ok(as_u64) = just_number.parse::<u64>() {
                        return as_u64;
                    }
                }
            }
        } else {
            error!("Error reading /proc/{}/status", my_pid);
            return 0;
        }
    }
    error!("Failed to parse a VmRSS value out of /proc/{}/status!", my_pid);
    return 0;
}

#[cfg(test)]
mod tests {
use util;
#[test]
fn mem_used_kb_parses_something()
{
    assert!(util::mem_used_kb() > 0);
}
}

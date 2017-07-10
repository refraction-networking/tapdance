#[macro_use]
extern crate arrayref;
extern crate lazycell;
extern crate libc;
#[macro_use]
extern crate log;
extern crate mio;
extern crate pnet;
extern crate protobuf;
extern crate rand;
extern crate time;
extern crate tuntap;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Read};
use std::mem::transmute;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;
use time::{get_time, precise_time_ns};

use mio::{Events, Poll};
use mio::unix::UnixReady;
use protobuf::core::parse_from_reader;
use tuntap::{TunTap,IFF_TUN};

// Must go before all other modules so that the report! macro will be visible.
#[macro_use]
pub mod logging;

pub mod bufferable_ssl;
pub mod bufferable_tcp;
pub mod buffered_tunnel;
pub mod c_api;
pub mod client_driver;
pub mod client_passive_driver;
pub mod client_ssl_driver;
pub mod covert_tcp_driver;
pub mod direction_pair;
pub mod elligator;
pub mod event_hook;
pub mod evented_ssl_eavesdropper;
pub mod flow_tracker;
pub mod mem_open_ssl;
pub mod process_packet;
pub mod protocol_cli2sta;
pub mod protocol_outer_framing;
pub mod protocol_sta2cli;
pub mod rereg_queuer;
pub mod session_error;
pub mod session_id;
pub mod signalling;
pub mod stream_traits;
pub mod tapdance_session;
pub mod token_map;
pub mod util;

use client_driver::ClientDriver;
use client_passive_driver::ClientPassiveDriver;
use client_ssl_driver::ClientSSLDriver;
use covert_tcp_driver::CovertTCPDriver;
use flow_tracker::FlowTracker;
use session_id::SessionId;
use signalling::ClientConf;
use tapdance_session::TapdanceSession;

// Global program state for one instance of a TapDance station process.
pub struct PerCoreGlobal
{
    priv_key: [u8; 32],

    pub flow_tracker: FlowTracker,

    tun: TunTap,

    cli_psv_driver: ClientPassiveDriver,
    cli_ssl_driver: ClientSSLDriver,
    cov_tcp_driver: CovertTCPDriver,
    cli_psv_poll: Poll,
    cli_ssl_poll: Poll,
    cov_tcp_poll: Poll,

    // For retrieving a TapdanceSession object by its SessionId.
    pub id2sess: HashMap<SessionId, Rc<RefCell<TapdanceSession>>>,

    // Just some scratch space for mio.
    events_buf: Events,

    // The u32 is a *host-order* Ipv4 address. While an IP address is present in
    // this set, the station will immediately error out all new sessions to it.
    overloaded_decoys: HashSet<u32>,

    pub stats: PerCoreStats,
}

// Tracking of some pretty straightforward quantities
pub struct PerCoreStats
{
    pub elligator_this_period: u64,
    pub packets_this_period: u64,
    pub tcp_packets_this_period: u64,
    pub tls_packets_this_period: u64,
    pub bytes_this_period: u64,
    pub reconns_this_period: u64,
    pub tls_bytes_this_period: u64,
    pub port_443_syns_this_period: u64,
    pub cli2cov_raw_etherbytes_this_period: u64,

    // CPU time counters (cumulative)
    tot_usr_us: i64,
    tot_sys_us: i64,
    // For computing measurement duration (because period won't be exactly 1
    // sec). Value is nanoseconds since an unspecified epoch. (It's a time,
    // not a duration).
    last_measure_time: u64,
}

const OVERLOADED_DECOYS_PATH: &'static str =
    "/var/lib/tapdance/overloaded_decoys";
const CLIENT_CONF_PATH: &'static str = "/var/lib/tapdance/client_conf";
impl PerCoreGlobal
{
    fn new(priv_key: [u8; 32], the_lcore: i32) -> PerCoreGlobal
    {
        // If you find yourself wanting to support more tuns, be sure to also
        // add them to startup.sh.
        let tun = match the_lcore {
            0 => TunTap::new(IFF_TUN, "tun0").unwrap(),
            1 => TunTap::new(IFF_TUN, "tun1").unwrap(),
            2 => TunTap::new(IFF_TUN, "tun2").unwrap(),
            3 => TunTap::new(IFF_TUN, "tun3").unwrap(),
            4 => TunTap::new(IFF_TUN, "tun4").unwrap(),
            5 => TunTap::new(IFF_TUN, "tun5").unwrap(),
            6 => TunTap::new(IFF_TUN, "tun6").unwrap(),
            7 => TunTap::new(IFF_TUN, "tun7").unwrap(),
            8 => TunTap::new(IFF_TUN, "tun8").unwrap(),
            9 => TunTap::new(IFF_TUN, "tun9").unwrap(),
            10 => TunTap::new(IFF_TUN, "tun10").unwrap(),
            11 => TunTap::new(IFF_TUN, "tun11").unwrap(),
            12 => TunTap::new(IFF_TUN, "tun12").unwrap(),
            13 => TunTap::new(IFF_TUN, "tun13").unwrap(),
            14 => TunTap::new(IFF_TUN, "tun14").unwrap(),
            15 => TunTap::new(IFF_TUN, "tun15").unwrap(),
            // If you find yourself wanting to support more tuns, be sure to
            // also add them to startup.sh!!!
            _ => panic!("lcore id > 15. Our tuns only go to 15."),
        };
        tun.set_up().unwrap();

        PerCoreGlobal {
            priv_key: priv_key,

            tun: tun,

            cli_psv_driver: ClientPassiveDriver::new(),
            cli_ssl_driver: ClientSSLDriver::new(),
            cov_tcp_driver: CovertTCPDriver::new(),
            cli_psv_poll: Poll::new().unwrap(),
            cli_ssl_poll: Poll::new().unwrap(),
            cov_tcp_poll: Poll::new().unwrap(),
            events_buf: Events::with_capacity(4096),

            flow_tracker: FlowTracker::new(),
            id2sess: HashMap::new(),
            overloaded_decoys: HashSet::new(),

            stats: PerCoreStats::new(),
        }
    }
    fn update_overloaded_decoys(&mut self)
    {
        let f = match File::open(OVERLOADED_DECOYS_PATH) {
            Ok(f) => f,
            Err(e) => {
                error!("Can't open {}:{:?}", OVERLOADED_DECOYS_PATH, e);
                return }
        };

        self.overloaded_decoys.clear();

        let buf_f = BufReader::new(f);
        for l in buf_f.lines() {
            let line = match l {
                Ok(the_l) => the_l,
                Err(e) => {
                    error!("{}: Read err {:?}", OVERLOADED_DECOYS_PATH, e);
                    return;
                }
            };

            let octets: Vec<&str> = line.split('.').collect();
            if octets.len() != 4 {
                warn!("MALFORMED {} line: {}", OVERLOADED_DECOYS_PATH, line);
                continue;
            }
            if let (Ok(a), Ok(b), Ok(c), Ok(d)) =
                (u8::from_str(octets[0]),
                 u8::from_str(octets[1]),
                 u8::from_str(octets[2]),
                 u8::from_str(octets[3]))
            {
                self.overloaded_decoys.insert(((a as u32) << 24) | 
                                              ((b as u32) << 16) | 
                                              ((c as u32) <<  8) | 
                                              ((d as u32)      ));
            } else {
                warn!("Malformed dotted quad in {}: {}",
                      OVERLOADED_DECOYS_PATH, line);
            }
        }
        info!("Successfully updated overloaded_decoys (now {} of them).",
              self.overloaded_decoys.len());
    }

    fn cli_ssl_drop_sessions(&mut self)
    {
        for session_id in self.cli_ssl_driver.sessions_to_drop.drain(..) {
            let (bidi_uniq_tok, upl_uniq_tok, cov_uniq_tok) = {
                if let Some(td_rc) = self.id2sess.get(&session_id) {
                    let mut sess = td_rc.borrow_mut();
                    (sess.cli_pair.take_bidi_tok(),
                    sess.cli_pair.take_upl_tok(), sess.cov.take_tok())
                }
                else { (None, None, None) }
            };
            self.id2sess.remove(&session_id);
            if let Some(uniq_tok) = bidi_uniq_tok {
                self.cli_ssl_driver.tok2sess.remove(uniq_tok);
            }
            if let Some(uniq_tok) = cov_uniq_tok {
                self.cov_tcp_driver.tok2sess.remove(uniq_tok);
            }
            if let Some(uniq_tok) = upl_uniq_tok {
                self.cli_psv_driver.tok2sess.remove(uniq_tok);
            }
        }
    }
    fn cli_psv_drop_sessions(&mut self)
    {
        for session_id in self.cli_psv_driver.sessions_to_drop.drain(..) {
            let (bidi_uniq_tok, upl_uniq_tok, cov_uniq_tok) = {
                if let Some(td_rc) = self.id2sess.get(&session_id) {
                    let mut sess = td_rc.borrow_mut();
                    (sess.cli_pair.take_bidi_tok(),
                    sess.cli_pair.take_upl_tok(), sess.cov.take_tok())
                }
                else { (None, None, None) }
            };
            self.id2sess.remove(&session_id);
            if let Some(uniq_tok) = bidi_uniq_tok {
                self.cli_ssl_driver.tok2sess.remove(uniq_tok);
            }
            if let Some(uniq_tok) = cov_uniq_tok {
                self.cov_tcp_driver.tok2sess.remove(uniq_tok);
            }
            if let Some(uniq_tok) = upl_uniq_tok {
                self.cli_psv_driver.tok2sess.remove(uniq_tok);
            }
        }
    }
    fn cov_tcp_drop_sessions(&mut self)
    {
        for session_id in self.cov_tcp_driver.sessions_to_drop.drain(..) {
            let (bidi_uniq_tok, upl_uniq_tok, cov_uniq_tok) = {
                if let Some(td_rc) = self.id2sess.get(&session_id) {
                    let mut sess = td_rc.borrow_mut();
                    (sess.cli_pair.take_bidi_tok(),
                    sess.cli_pair.take_upl_tok(), sess.cov.take_tok())
                }
                else { (None, None, None) }
            };
            self.id2sess.remove(&session_id);
            if let Some(uniq_tok) = bidi_uniq_tok {
                self.cli_ssl_driver.tok2sess.remove(uniq_tok);
            }
            if let Some(uniq_tok) = cov_uniq_tok {
                self.cov_tcp_driver.tok2sess.remove(uniq_tok);
            }
            if let Some(uniq_tok) = upl_uniq_tok {
                self.cli_psv_driver.tok2sess.remove(uniq_tok);
            }
        }
    }
    fn do_queued_session_drops(&mut self)
    {
        self.cli_ssl_drop_sessions();
        self.cli_psv_drop_sessions();
        self.cov_tcp_drop_sessions();
    }
}
impl PerCoreStats
{
    fn new() -> PerCoreStats
    {
        PerCoreStats { elligator_this_period: 0,
                       packets_this_period: 0,
                       tcp_packets_this_period: 0,
                       tls_packets_this_period: 0,
                       bytes_this_period: 0,
                       reconns_this_period: 0,
                       tls_bytes_this_period: 0,
                       port_443_syns_this_period: 0,
                       cli2cov_raw_etherbytes_this_period: 0,

                       tot_usr_us: 0,
                       tot_sys_us: 0,
                       last_measure_time: precise_time_ns() }
    }
    fn periodic_status_report(&mut self, tracked: usize, sessions: usize)
    {
        let cur_measure_time = precise_time_ns();
        let (user_secs, user_usecs, sys_secs, sys_usecs) =
            c_api::c_get_cpu_time();
        let user_microsecs: i64 = user_usecs + 1000000 * user_secs;
        let sys_microsecs: i64 = sys_usecs + 1000000 * sys_secs;

        let measured_dur_ns = cur_measure_time - self.last_measure_time;
        let total_cpu_usec = (user_microsecs + sys_microsecs)
                     - (self.tot_usr_us + self.tot_sys_us);
        report!("status {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
                self.elligator_this_period,
                self.packets_this_period,
                self.tls_packets_this_period,
                self.bytes_this_period,
                total_cpu_usec,
                get_rounded_time(),
                measured_dur_ns,
                util::mem_used_kb(),
                self.reconns_this_period,
                tracked,
                sessions,
                self.tls_bytes_this_period,
                self.port_443_syns_this_period,
                self.cli2cov_raw_etherbytes_this_period,
                c_api::c_get_global_cli_download_count());

        self.elligator_this_period = 0;
        self.packets_this_period = 0;
        self.tcp_packets_this_period = 0;
        self.tls_packets_this_period = 0;
        self.bytes_this_period = 0;
        self.reconns_this_period = 0;
        self.tls_bytes_this_period = 0;
        self.port_443_syns_this_period = 0;
        self.cli2cov_raw_etherbytes_this_period = 0;
        c_api::c_reset_global_cli_download_count();

        self.tot_usr_us = user_microsecs;
        self.tot_sys_us = sys_microsecs;
        self.last_measure_time = cur_measure_time;
    }
}
fn periodic_active_decoy_report(id2sess: &HashMap<SessionId,
                                                  Rc<RefCell<TapdanceSession>>>)
{
    let mut countup: HashMap<String, usize> =
        HashMap::with_capacity(id2sess.len());
    for (_session_id, td_rc) in id2sess.iter() {
        let decoy_ip = td_rc.borrow().decoy_ip.clone();
        let the_entry = countup.entry(decoy_ip).or_insert(0);
        *the_entry += 1;
    }
    let mut active_report = String::with_capacity(64 * 1024);
    active_report.push_str("activedecoys");
    for (decoy, count) in countup.iter() {
        active_report.push_str(" ");
        active_report.push_str(count.to_string().as_str());
        active_report.push_str("@");
        active_report.push_str(decoy.as_str());
    }
    active_report.push_str("\n");
    info!("{}", active_report);
    c_api::c_write_reporter(active_report);
}
fn periodic_failed_decoy_report()
{
    let mut failed_report = String::with_capacity(64 * 1024);
    failed_report.push_str("faileddecoys");
    let mut fail_map = unsafe{ &mut *(c_api::get_global_failure_map_rawptr()
                                        as *mut HashMap<String, usize>) };
    for (sni_ip, count) in fail_map.drain() {
        let v: Vec<&str> = sni_ip.split(' ').collect();
        if v.len() == 2 {
            let sni = v[0];
            let ip_addr = v[1];
            failed_report.push_str(" ");
            failed_report.push_str(count.to_string().as_str());
            failed_report.push_str("@");
            failed_report.push_str(ip_addr);
            failed_report.push_str(",");
            failed_report.push_str(sni);
        } else {
            warn!("Client reported a malformed decoy failure: {}", sni_ip);
        }
    }
    failed_report.push_str("\n");
    info!("{}", failed_report);
    c_api::c_write_reporter(failed_report);
}
#[no_mangle]
pub extern "C" fn rust_periodic_report(ptr: *mut PerCoreGlobal)
{
    let mut global = unsafe { &mut *ptr };
    global.stats.periodic_status_report(
        global.flow_tracker.count_tracked_flows(), global.id2sess.len());
    periodic_active_decoy_report(&global.id2sess);
    periodic_failed_decoy_report();
}

fn get_rounded_time() -> i64
{
    let timespec = get_time();
    if timespec.nsec >= 500000000 { timespec.sec + 1 }
    else { timespec.sec }
}

#[repr(C)]
pub struct RustGlobalsStruct
{
    global: *mut PerCoreGlobal,
    cli_conf: *mut ClientConf,
    fail_map: *mut HashMap<String, usize>,
}

#[no_mangle]
pub extern "C" fn rust_init(lcore_id: i32, ckey: *const u8)
-> RustGlobalsStruct
{
    let key = *array_ref!(unsafe{std::slice::from_raw_parts(ckey, 32 as usize)},
                          0, 32);

    logging::init(log::LogLevel::Debug, lcore_id);

    let s = format!("/tmp/tapdance-reporter-{}.fifo", lcore_id);
    c_api::c_open_reporter(s);
    report!("reset");

    let mut cli_conf = ClientConf::new();
    cli_conf.set_generation(0);
    let fail_map: HashMap<String, usize> = HashMap::with_capacity(4096);
    let global = PerCoreGlobal::new(key, lcore_id);

    debug!("Initialized rust core {}", lcore_id);

    RustGlobalsStruct { global: unsafe { transmute(Box::new(global)) },
                        fail_map: unsafe { transmute(Box::new(fail_map)) },
                        cli_conf: unsafe { transmute(Box::new(cli_conf)) } }
}

// Can be called from C. Updates the "global" ClientConf with the current
// contents of the file /var/lib/tapdance/client_conf.
#[no_mangle]
pub extern "C" fn rust_update_cli_conf(ptr: *mut ClientConf)
{
    let mut f = match File::open(CLIENT_CONF_PATH) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to read {}: {:?}", CLIENT_CONF_PATH, e);
            return;
        }
    };
    let mut global_conf = unsafe { &mut *ptr };
    *global_conf = match parse_from_reader::<ClientConf>(&mut f as &mut Read) {
        Ok(the_new_conf) => the_new_conf,
        Err(e) => {
            error!("Failed to parse {}: {:?}", CLIENT_CONF_PATH, e);
            return;
        }
    };
    info!("Successfully updated ClientConf. New generation number: {}",
          global_conf.get_generation());
}

// Can be called from C. Updates the PerCoreGlobal's overloaded_decoys with the
// contents of "/var/lib/tapdance/overloaded_decoys".
#[no_mangle]
pub extern "C" fn rust_update_overloaded_decoys(ptr: *mut PerCoreGlobal)
{
    let mut global = unsafe { &mut *ptr };
    global.update_overloaded_decoys();
}

// Called so we can tick the event loop forward. Must not block.
#[no_mangle]
pub extern "C" fn rust_event_loop_tick(ptr: *mut PerCoreGlobal)
{
    let mut global = unsafe { &mut *ptr };

    // TODO does this Duration::new(0,0) have any performance hit vs just 0?
    // TODO I want to catch_unwind() here, but Rust is warning about some pretty
    //      serious safety stuff when I try, and I think I agree with it.
    let res1 = global.cov_tcp_poll.poll(&mut global.events_buf,
                                        Some(Duration::new(0,0)));
    if res1.is_err() { error!("cov TCP poll error: {:?}", res1); }
    for event in &global.events_buf {
        global.cov_tcp_driver.process_event(&event.token(),
                                            UnixReady::from(event.readiness()));
    }

    let res2 = global.cli_ssl_poll.poll(&mut global.events_buf,
                                        Some(Duration::new(0,0)));
    if res2.is_err() { error!("cli SSL poll error: {:?}", res2); }
    for event in &global.events_buf {
        global.cli_ssl_driver.process_event(&event.token(),
                                            UnixReady::from(event.readiness()));
    }

    let res3 = global.cli_psv_poll.poll(&mut global.events_buf,
                                        Some(Duration::new(0,0)));
    if res3.is_err() { error!("cli eavesdropped SSL poll error: {:?}", res3); }
    for event in &global.events_buf {
        global.cli_psv_driver.process_event(&event.token(),
                                            UnixReady::from(event.readiness()));
    }

    global.do_queued_session_drops();

    global.cov_tcp_driver.rereg_queuer.do_cli_reregs(&global.cli_ssl_poll,
                                                       &global.cli_psv_poll,
                                                       &mut global.id2sess);
    global.cov_tcp_driver.rereg_queuer.do_cov_reregs(&global.cov_tcp_poll,
                                                       &mut global.id2sess);
    global.cli_ssl_driver.rereg_queuer().do_cli_reregs(&global.cli_ssl_poll,
                                                       &global.cli_psv_poll,
                                                       &mut global.id2sess);
    global.cli_ssl_driver.rereg_queuer().do_cov_reregs(&global.cov_tcp_poll,
                                                       &mut global.id2sess);
    global.cli_psv_driver.rereg_queuer().do_cli_reregs(&global.cli_ssl_poll,
                                                       &global.cli_psv_poll,
                                                       &mut global.id2sess);
    global.cli_psv_driver.rereg_queuer().do_cov_reregs(&global.cov_tcp_poll,
                                                       &mut global.id2sess);
}

// Drops TLS flows that took too long to send their first app data packet,
// RSTs decoy flows a couple of seconds after the client's FIN, and
// errors-out cli-stream-less sessions that took too long to get a new stream.
#[no_mangle]
pub extern "C" fn rust_periodic_cleanup(ptr: *mut PerCoreGlobal)
{
    let mut global = unsafe { &mut *ptr };
    global.flow_tracker.drop_stale_flows_and_RST_FINd();

    // Any session that hangs around for 30 seconds with a None cli stream
    // should be errored out. These check events are scheduled every time a
    // stream ends (token removed from driver map).
    global.cli_ssl_driver.check_sessions_progress(&global.id2sess);
    global.cli_psv_driver.check_sessions_progress(&global.id2sess);

    // Any stream that hangs around [longer than the system's largest timeout]
    // should be treated as broken.
    global.cli_ssl_driver.check_streams_progress(&global.id2sess);
    global.cli_psv_driver.check_streams_progress(&global.id2sess);
}

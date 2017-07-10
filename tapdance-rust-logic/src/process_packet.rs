use libc::size_t;
use std::cell::RefCell;
use std::net::{IpAddr,SocketAddr};
use std::os::raw::c_void;
use std::panic;
use std::rc::Rc;
use std::slice;
use std::str::FromStr;
use time::precise_time_ns;

use mio::PollOpt;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpPacket,TcpFlags};

use bufferable_ssl::BufferableSSL;
use client_driver::SchedSessionTimeout;
use bufferable_tcp::BufferableTCP;
use elligator;
use evented_ssl_eavesdropper::EventedSSLEavesdropper;
use flow_tracker::{Flow,WscaleAndMSS};
use PerCoreGlobal;
use session_error::SessionError;
use session_id::SessionId;
use tapdance_session::TapdanceSession;
use util;

const TLS_TYPE_APPLICATION_DATA: u8 = 0x17;
const SQUID_PROXY_ADDR: &'static str = "127.0.0.1";
const SQUID_PROXY_PORT: u16 = 1234;

const STREAM_TIMEOUT_NS: u64 = 120*1000*1000*1000; // 120 seconds

// The jumping off point for all of our logic. This function inspects a packet
// that has come in the tap interface. We do not yet have any idea if we care
// about it; it might not even be TLS. It might not even be TCP!
#[no_mangle]
pub extern "C" fn rust_process_packet(ptr: *mut PerCoreGlobal,
                                      raw_ethframe: *mut c_void,
                                      frame_len: size_t)
{
    let mut global = unsafe { &mut *ptr };

    let rust_view_len = frame_len as usize;
    let rust_view = unsafe {
        slice::from_raw_parts_mut(raw_ethframe as *mut u8, frame_len as usize)
    };
    global.stats.packets_this_period += 1;
    global.stats.bytes_this_period += rust_view_len as u64;

    let eth_pkt = match EthernetPacket::new(rust_view) {
        Some(pkt) => pkt,
        None => return,
    };
    let eth_payload = eth_pkt.payload();

    let ip_data = match eth_pkt.get_ethertype() {
        EtherTypes::Vlan => {
            if eth_payload[2] == 0x08 && eth_payload[3] == 0x00 {
                //let vlan_id: u16 = (eth_payload[0] as u16)*256
                //                 + (eth_payload[1] as u16);
                &eth_payload[4..]
            } else {
                return
            }
        },
        EtherTypes::Ipv4 => &eth_payload[0..],
        _ => return,
    };
    match Ipv4Packet::new(ip_data) {
        Some(pkt) => global.process_ipv4_packet(pkt, rust_view_len),
        None => return,
    }
}

fn is_tls_app_pkt(tcp_pkt: &TcpPacket) -> bool
{
    let payload = tcp_pkt.payload();
    payload.len() > 5 && payload[0] == TLS_TYPE_APPLICATION_DATA
}

impl PerCoreGlobal
{
    // frame_len is supposed to be the length of the whole Ethernet frame. We're
    // only passing it here for plumbing reasons, and just for stat reporting.
    fn process_ipv4_packet(&mut self, ip_pkt: Ipv4Packet, frame_len: usize)
    {
        // Ignore packets that aren't TCP
        if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return;
        }
        let tcp_pkt = match TcpPacket::new(ip_pkt.payload()) {
            Some(pkt) => pkt,
            None => return,
        };
        self.stats.tcp_packets_this_period += 1;

        // Ignore packets that aren't -> 443.
        // libpnet getters all return host order. Ignore the "u16be" in their
        // docs; interactions with pnet are purely host order.
        if tcp_pkt.get_destination() != 443 {
            return;
        }
        self.stats.tls_packets_this_period += 1; // (HTTPS, really)
        self.stats.tls_bytes_this_period += frame_len as u64;
        self.process_tls_pkt(&ip_pkt, &tcp_pkt);
    }

    // Takes an IPv4 packet
    // Assumes (for now) that TLS records are in a single TCP packet
    // (no fragmentation).
    // Fragments could be stored in the flow_tracker if needed.
    pub fn process_tls_pkt(&mut self,
                           ip_pkt: &Ipv4Packet,
                           tcp_pkt: &TcpPacket)
    {
        let flow = Flow::new(ip_pkt, tcp_pkt);

        if panic::catch_unwind(||{ tcp_pkt.payload(); }).is_err() {
            return;
        }

        let tcp_flags = tcp_pkt.get_flags();
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0
        {
            self.stats.port_443_syns_this_period += 1;
            self.flow_tracker.begin_tracking_flow(&flow,
                                                  tcp_pkt.packet().to_vec());
            return;
        }

        if !self.flow_tracker.tracking_at_all(&flow) {
            return;
        }

        // Note that FINs and RSTs are welcome in consume_tcp_pkt() as well.
        if !self.flow_tracker.consume_tcp_pkt_if_passive(&flow, tcp_pkt) {
            // EventedSSLEavesdropped::consume_tcp_pkt() said to drop the flow.
            self.flow_tracker.drop(&flow);
        }
        else if self.flow_tracker.is_td(&flow) {
            // Forward packets from established overt flows into the tun
            // interface, so that they'll reach forge_socket.
            self.forward_to_forge_socket(ip_pkt);
            if (tcp_flags & TcpFlags::FIN) != 0 {
                // This stream (overt flow) is ending. The client might come and
                // resume the TapDance session with a new stream, so leave the
                // overall session state intact. The is_hup event's processing
                // takes care of starting the BufferableSSL's cleanup.
                // FlowTracker::notice_fin() will schedule a RST to be sent to
                // the decoy server; forge_socket handles the FIN handshake.
                self.flow_tracker.notice_fin(&flow);
            }
        }
        else if (tcp_flags & TcpFlags::FIN) != 0 { // non-TD flow FINd => drop
            self.flow_tracker.drop(&flow);
            return;
        }

        if (tcp_flags & TcpFlags::RST) != 0 {
            // End connection, remove any relevant state.
            // TODO clean up TapDance session state, if any
            // (TODO i believe that the earlier forward_to_forge_socket would
            //  cause a clien is_error event to fire, which would then clean up
            //  the session. should confirm.)
            self.flow_tracker.drop(&flow);
            return;
        }

        // This is a non-RST/FIN packet of a flow we are tracking, but that is
        // not known to be TapDance. That means this might be a tag-bearing
        // first TLS app data packet: establish a TD session if so.
        if !self.flow_tracker.is_td(&flow) && is_tls_app_pkt(tcp_pkt) {
            // ...buuut don't bother checking these known-irrelevant addresses:
            // coming from U. Michigan (35.0.0.0/9)
            // going to Google CDN servers in Michigan (192.122.185.0/24)
            // coming from windyegret's internet connection (192.122.200.253)
            // coming from more of U. Michigan (141.212.0.0/14)
            let src = ip_pkt.get_source().octets();
            let dest = ip_pkt.get_destination().octets();
            if src[0] == 35 && (src[1] & 128 == 0) || 
               dest[0] == 192 && dest[1] == 122 && dest[2] == 185 ||
               src[0]==192 && src[1]==122 && src[2]==200 && src[3]==253 ||
               src[0] == 141 && (src[2] & 252) == 212 ||
               !self.try_establish_tapdance(&flow, tcp_pkt)
            {
                // No tag in first TLS app data packet ==> definitely not TD.
                self.flow_tracker.drop(&flow);
            }
        }
    }

    fn forward_to_forge_socket(&mut self, ip_pkt: &Ipv4Packet)
    {
        let ip_len = ip_pkt.packet().len();

        // TODO: see if the PI flag to the TUN interface can actually take care
        // of this for us
        let mut tun_pkt = Vec::with_capacity(ip_len+4);
        // These mystery bytes are a link-layer header; the kernel "receives"
        // tun packets as if they were really physically "received". Since they
        // weren't physically received, they do not have an Ethernet header. It
        // looks like the tun setup has its own type of header, rather than just
        // making up a fake Ethernet header.
        tun_pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00]);
        tun_pkt.extend_from_slice(ip_pkt.packet());

        // Send into tun device (can fail, but these are best-effort IP packets)
        self.tun.send(tun_pkt).unwrap_or_else(|e|{
            warn!("failed to send packet into tun: {}", e); 0});
        self.stats.cli2cov_raw_etherbytes_this_period += ip_len as u64;
    }

    // Inspects a TLS app data packet for a TapDance tag. If found, establishes
    // the flow as a TapDance stream (and starts a new session, if 1st stream).
    // Returns true iff a TapDance stream was successfully established.
    fn try_establish_tapdance(&mut self,
                              flow: &Flow,
                              tcp_pkt: &TcpPacket) -> bool
    {
        let tag_payload = elligator::extract_telex_tag(&self.priv_key,
                                                       &tcp_pkt.payload());
        self.stats.elligator_this_period += 1;
        if tag_payload.len() < TAG_FLAGS_LEN + TAG_M_KEY_LEN + TAG_SRV_RND_LEN +
                               TAG_CLI_RND_LEN + TAG_CON_ID_LEN
        {
            return false;
        }

        if tag_payload[0] & 128u8 == 0 { // traditional bidi forged TLS

            // Decoy will ACK current packet with this value. (Host-order).
            let expect_ack =
                tcp_pkt.get_sequence()
                       .wrapping_add(tcp_pkt.payload().len() as u32);

            let wscale_and_mss =
                self.flow_tracker.mark_tapdance_flow(flow, expect_ack);

            self.establish_bidi(tcp_pkt, flow, &tag_payload, wscale_and_mss)

        } else { // upload-only eavesdropped TLS
        
            // (don't mark as TD in FlowTracker until you have the Rc<RefCell>)

            self.establish_upload_only(tcp_pkt, flow, &tag_payload)
        }
    }

    pub fn establish_bidi(&mut self,
                          tcp_pkt: &TcpPacket, flow: &Flow,
                          tag_payload: &Vec<u8>,
                          wscale_and_mss: WscaleAndMSS) -> bool
    {
        let (_, master_key, server_random, client_random, session_id) =
            parse_tag_payload(tag_payload);

        let (tcp_ts, tcp_ts_ecr) = util::get_tcp_timestamps(tcp_pkt);

        let mut client_ssl = BufferableSSL::new(session_id);
        let ssl_success =
            client_ssl.construct_forged_ssl(
                tcp_pkt, flow, &wscale_and_mss, tcp_ts, tcp_ts_ecr, 
                master_key, client_random, server_random);
        if ssl_success {
            let (is_a_reconnect, rc, cov_error) =
                self.create_or_recall_tapdance_session(session_id);

            let ref mut td = rc.borrow_mut();

            let tok = self.cli_ssl_driver.tok2sess.insert(rc.clone());
            if !td.cli_pair.set_bidi(client_ssl, tok, &mut self.cli_ssl_poll) {
                td.end_whole_session_error(SessionError::ClientProtocol);
                return false;
            }
            td.expect_bidi_reconnect = false;

            if let Some(cov_err) = cov_error {
                td.end_whole_session_error(cov_err);
                self.cli_ssl_driver
                    .sessions_to_drop.push_back(td.session_id);
            }

            let src_oct1: u8 = ((flow.src_ip & 0xff000000u32) >> 24) as u8;
            let src_oct2: u8 = ((flow.src_ip & 0x00ff0000u32) >> 16) as u8;

            if is_a_reconnect {
                self.stats.reconns_this_period += 1;
                td.send_reconnect_to_client();
                td.cov_read_cli_write(&mut self.cov_tcp_driver.rereg_queuer,
                                      false);
                if td.both_half_closed() { // if errored, must mark for drop
                    self.cli_ssl_driver.sessions_to_drop
                                       .push_back(td.session_id);
                }
            } else {
                let decoy_ip_str = util::inet_htoa(flow.dst_ip);
                info!("newsession {} {}.{}.x.x:{} -> {}:{}",
                      session_id, src_oct1, src_oct2, flow.src_port,
                      decoy_ip_str, flow.dst_port);
                td.decoy_ip = decoy_ip_str;
                if self.overloaded_decoys.contains(&flow.dst_ip) {
                    td.end_whole_session_error(SessionError::DecoyOverload);
                    self.cli_ssl_driver.sessions_to_drop
                                       .push_back(td.session_id);
                }
            }
            self.cli_ssl_driver.stream_timeouts.push_back(
                SchedSessionTimeout {
                    drop_time: precise_time_ns() + STREAM_TIMEOUT_NS,
                    id: session_id,
                    stream_count: td.cli_pair.stream_count() });
            info!("newstream {} {}.{}.x.x:{} -> {}:{}", session_id,
                    src_oct1, src_oct2, flow.src_port,
                    util::inet_htoa(flow.dst_ip), flow.dst_port);
            true
        } else {
            error!("make_forged_tls() returned 0! Tagged TLS not picked up \
                    as a TapDance stream :(");
            false
        }
    }
    pub fn establish_upload_only(&mut self, tcp_pkt: &TcpPacket, flow: &Flow,
                                 tag_payload: &Vec<u8>) -> bool
    {
        let (_, master_key, server_random, client_random, session_id) =
            parse_tag_payload(tag_payload);

        let mut passive_ssl = EventedSSLEavesdropper::new(session_id);
        let ssl_success = passive_ssl.construct_eavesdropped_ssl(
            tcp_pkt, master_key, client_random, server_random);
        if ssl_success
        {
            if let Some(rc) = self.id2sess.get(&session_id)
            {
                let inserted_tok =
                    self.cli_psv_driver.tok2sess.insert(rc.clone());

                let ref mut td = rc.borrow_mut();
                if !td.cli_pair.set_passive_uploader(passive_ssl, inserted_tok,
                                                     &self.cli_psv_poll)
                {
                    td.end_whole_session_error(SessionError::ClientProtocol);
                    return false;
                }
                td.expect_uploader_reconnect = false;

                // TODO? self.stats.reconns_UPL_this_period += 1;
                // TODO? (goes thru bidi) td.send_UPL_reconnect_to_client();

                self.flow_tracker.mark_passive_td(flow, rc.clone());

                self.cli_ssl_driver.stream_timeouts.push_back(
                    SchedSessionTimeout {
                        drop_time: precise_time_ns() + STREAM_TIMEOUT_NS,
                        id: session_id,
                        stream_count: td.cli_pair.stream_count() });
                report!("newuploader {} {}:{} -> {}:{}", session_id,
                    util::inet_htoa(flow.src_ip), flow.src_port,
                    util::inet_htoa(flow.dst_ip), flow.dst_port);

                true
            }
            else
            {
                error!("This new upload-only stream does not belong to an \
                        ongoing session. A session's first stream must be \
                        bidi. Session ID: {}", session_id);
                report!("newuploader {} {}:{} -> {}:{}", session_id,
                    util::inet_htoa(flow.src_ip), flow.src_port,
                    util::inet_htoa(flow.dst_ip), flow.dst_port);
                report!("error {} {}", session_id,
                        SessionError::ClientProtocol.to_string());
                // (passive_ssl goes out of scope, "deluploader")
                false
            }
        }
        else
        {
            error!("make_forged_memory_tls() returned 0! Tagged TLS not picked \
                    up as a passive TapDance stream :(");
            false
        }
    }

    // Lookup the ongoing session with ID session_id, if it exists. If it does
    // not, make a new one (including initiating the Squid TCP connection).
    // Returns: Bool is whether the session was already there.
    // Option<SessionError> is to be filled if session creation failed.
    fn create_or_recall_tapdance_session(&mut self, session_id: SessionId)
    -> (bool, Rc<RefCell<TapdanceSession>>, Option<SessionError>)
    {
        let ref mut cov_tcp_poll = self.cov_tcp_poll;
        let ref mut tok_map = self.cov_tcp_driver.tok2sess;
        let recalled = self.id2sess.contains_key(&session_id);
        let mut cov_err = None;
        let rc = self.id2sess.entry(session_id).or_insert_with(|| 
        {
            let td_rc =
                Rc::new(RefCell::new(TapdanceSession::new(session_id)));

            // New proxy connection to local proxy. unwrap() relies on
            // SQUID_PROXY_ADDR being a valid constant.
            let dest = IpAddr::from_str(SQUID_PROXY_ADDR).unwrap();
            let sock_addr = SocketAddr::new(dest, SQUID_PROXY_PORT);

            // NOTE: this mio version of TcpStream is nonblocking!
            if let Ok(sock) = ::mio::tcp::TcpStream::connect(&sock_addr) {
                let ref mut td = td_rc.borrow_mut();
                td.cov.set_stream(BufferableTCP::new(sock));
                let inserted_tok = tok_map.insert(td_rc.clone());
                td.cov.register(cov_tcp_poll, inserted_tok.val(),
                                util::all_unix_events(), PollOpt::edge())
                  .unwrap_or_else(|e|{error!("tcp_driver 1st reg: {}", e);});
                td.cov.set_tok(inserted_tok);
            } else {
                // TODO: actually, we're more concerned with out-of-fds, which
                // is more like StationInternal. But, how to distinguish?
                cov_err = Some(SessionError::CovertStream);
            }
            td_rc
        });
        (recalled, rc.clone(), cov_err)
    }
} // impl PerCoreGlobal

// These consts tie the slice indexing in establish_tapdance_stream_from_tag()
// to the length check in try_establish_tapdance().
// Current tag payload format:
//===============================================================
// 1 byte................flags
// 48 bytes              master_key
// 32 bytes..............server_random
// 32 bytes              client_random
// 16 bytes..............connection_id
const TAG_FLAGS_LEN: usize = 1;
const TAG_M_KEY_LEN: usize = 48;
const TAG_SRV_RND_LEN: usize = 32;
const TAG_CLI_RND_LEN: usize = 32;
const TAG_CON_ID_LEN: usize = 16;

// Assumes you will only call it after checking
// if tag_payload.len() >= TAG_FLAGS_LEN + TAG_M_KEY_LEN + TAG_SRV_RND_LEN +
//                         TAG_CLI_RND_LEN + TAG_CON_ID_LEN
fn parse_tag_payload(tag_payload: &Vec<u8>)
-> (u8, &[u8], &[u8], &[u8], SessionId)
{
    let mut offset = 0;

    let flags = tag_payload[offset];
    offset += TAG_FLAGS_LEN;

    let master_key = &tag_payload[offset..offset+TAG_M_KEY_LEN];
    offset += TAG_M_KEY_LEN;

    let server_random = &tag_payload[offset..offset+TAG_SRV_RND_LEN];
    offset += TAG_SRV_RND_LEN;

    let client_random = &tag_payload[offset..offset+TAG_CLI_RND_LEN];
    offset += TAG_CLI_RND_LEN;

    let session_id_slice = &tag_payload[offset..offset+TAG_CON_ID_LEN];
    // (do `offset += TAG_CON_ID_LEN` here if you need to read further)
    let session_id = SessionId::new(
        array_ref![session_id_slice,0,TAG_CON_ID_LEN]);

    (flags, master_key, server_random, client_random, session_id)
}

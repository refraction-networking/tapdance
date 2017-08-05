use pnet::packet::tcp::TcpPacket;
use protobuf::Message;

use bufferable_tcp::BufferableTCP;
use buffered_tunnel::BufferedTunnel;
use c_api;
use direction_pair::DirectionPair;
use protocol_sta2cli;
use protocol_sta2cli::empty_proto_frame_with_len;
use rereg_queuer::ReregQueuer;
use session_error::SessionError;
use session_id::SessionId;
use signalling::{ClientToStation, C2S_Transition, S2C_Transition};
use stream_traits::{BufStat, ReadStat, ShutStat, WriteStat, StreamReceiver};

// How many burst sizes (currently 16KiB, max SSL record size) worth of data
// may a single execution of cov_read_cli_write() transfer?
const MAX_COV2CLI_BURST: usize = 4;
// similar
const MAX_CLI2COV_BURST: usize = 4;

// For only tapdance flows (TLS/proxy/etc state)
pub struct TapdanceSession
{
    pub session_id: SessionId,
    pub cov: BufferedTunnel<BufferableTCP>,
    pub cli_pair: DirectionPair,
    sent_init_to_client: bool,
    sent_close_to_client: bool,
    pub expect_bidi_reconnect: bool,
    pub expect_uploader_reconnect: bool,
    already_errored_out: bool,
    pub decoy_ip: String,
    pub received_gen: bool, // false until our first protobuf from client (first
                            // reconnect)
    pub cli2cov_bytes_tot:  usize,
    pub cov2cli_bytes_tot:  usize,
}
impl TapdanceSession
{
    pub fn new(session_id: SessionId) -> TapdanceSession
    {
        TapdanceSession { session_id: session_id,
                          cov: BufferedTunnel::new(),
                          cli_pair: DirectionPair::new(),
                          sent_init_to_client: false,
                          sent_close_to_client: false,
                          expect_bidi_reconnect: false,
                          expect_uploader_reconnect: false,
                          already_errored_out: false,
                          decoy_ip: String::new(),
                          received_gen: false,
                          cli2cov_bytes_tot: 0,
                          cov2cli_bytes_tot: 0 }
    }
    // True if read+write of both directions are closed (session is done).
    pub fn both_half_closed(&self) -> bool
    {
        self.cli_pair.half_closed() && self.cov.half_closed()
    }

    pub fn send_init_to_client(&mut self)
    {
        if self.sent_init_to_client {
            return;
        }
        let data = protocol_sta2cli::make_session_init_msg();
        if !self.nonfreezy_cli_write(data.as_slice()) {
            self.end_whole_session_error(SessionError::ClientStream);
        }
        self.sent_init_to_client = true;
    }
    pub fn send_reconnect_to_client(&mut self)
    {
        let data = protocol_sta2cli::make_confirm_reconnect_msg();
        if self.cli_pair.write_skipping_buffer(data.as_slice())
                         == WriteStat::Error
        {
            self.end_whole_session_error(SessionError::ClientStream);
        }
    }

    // If not called from (ultimately) within a driver, you must follow it up
    // with your own self.some_driver.sessions_to_drop.push_back(td.session_id).
    pub fn end_whole_session_error(&mut self, why: SessionError)
    {
        if !self.already_errored_out {
            self.already_errored_out = true;
            info!("error {} {}", self.session_id, why.to_string());
        } else {
            info!("duperror {} {}", self.session_id, why.to_string());
        }
        // A couple of uses of this function are due to SSL failing
        // to send, hahaha... oh well, it won't break, just won't send.
        let data = protocol_sta2cli::make_err_msg(why);
        let _ = self.nonfreezy_cli_write(data.as_slice());
        // nonfreezy_cli_write() will not flush the buffer if there was stuff.
        // We don't actually care about stalls now that there's an error, so
        // ok to flush without handling any potential reads-were-paused stalls.
        self.cli_pair.drain_send_buf();

        self.cli_pair.unclean_shutdown();
        self.cov.unclean_shutdown();
        self.cli_pair.half_close();
        self.cov.half_close();
    }

    // Helper function for when we are injecting control messages, rather than
    // just processing data with the do_X_read_Y_write() functions.
    // Returns success: if false, you should consider this whole session broken.
    pub fn nonfreezy_cli_write(&mut self, data: &[u8]) -> bool
    {
        self.cli_pair.write_no_flush(&data) != WriteStat::Error
    }
    fn send_cli_shutdown_msg(&mut self)
    {
        if self.sent_close_to_client {
            return;
        }
        let shut_msg = protocol_sta2cli::make_session_close_msg();
        if !self.nonfreezy_cli_write(shut_msg.as_slice()) {
            error!("Error while writing shutdown msg! Bailing on {}",
                    self.session_id);
            self.end_whole_session_error(SessionError::ClientStream);
        }
        self.sent_close_to_client = true;
    }
    pub fn handle_cli_bidi_hup(&mut self)
    {
        self.cli_pair.set_bidi_read_closed();
        if    self.expect_bidi_reconnect
           || !self.cli_pair.bidi_is_active_uploader
          // || self.cli_pair.bidi_has_yielded <== do NOT need this; implied by
          //                                       !bidi_is_active_uploader
        {
            // They're coming back, so it's ok to close our sending direction of
            // the TLS stream now: not-yet-buffered data from cov is not lost
            // since it can just go in the next stream.
            if self.cli_pair.bidi_clean_shutdown() == ShutStat::Error {
                self.end_whole_session_error(SessionError::ClientStream);
            }
        }
        else if self.cov.half_close_pending() {
            // They're NOT coming back, so our sending direction of this TLS
            // stream must remain open until all data from cov has been sent.
            // Simply not closing here is enough: eventually the cov side will
            // also half-close, which will complete the shutdown of this stream.
            // TODO HACK what we actually want is the above!
            // TODO HACK really should not half-close cli here, but it appears
            // that, at least for ssh, cov will not respond to the half-close.
            // The client currently only full-closes, so this is ok for now.
            self.send_cli_shutdown_msg();
            self.cli_pair.half_close();
            // TODO these unclean_shutdown()s are just to guarantee that both
            // directions' half-closes will appear done. Once we have half-
            // closing working more gracefully, don't force it like this.
            self.cli_pair.unclean_shutdown(); // HACK!
            self.cov.unclean_shutdown(); // HACK!
        } else {
            // The client is expected to always tell us what a TLS stream
            // close means; treat failure to do so as a broken session.
            self.end_whole_session_error(SessionError::ClientProtocol);
        }
    }
    pub fn handle_cli_uploader_hup(&mut self)
    {
        if    self.expect_uploader_reconnect 
           || self.cli_pair.bidi_is_active_uploader
          // || self.cli_pair.uploader_has_yielded <= do NOT need this; implied
          //                                          by bidi_is_active_uploader
        {
            self.cli_pair.drop_passive_uploader();
        } else {
            // The client is expected to always tell us what a TLS stream
            // close means; treat failure to do so as a broken session.
            self.end_whole_session_error(SessionError::ClientProtocol);
        }
    }
    pub fn handle_cov_stream_hup(&mut self)
    {
        self.cov.set_read_closed();
        self.send_cli_shutdown_msg();
        self.cli_pair.half_close();
    }







    // Moves some data in the covert->client direction.
    pub fn cov_read_cli_write(&mut self, rereg_queuer: &mut ReregQueuer,
                              must_do_all_reads_now: bool)
    {
        if must_do_all_reads_now {
            while self.do_one_cov_read_cli_write(true) {}
        } else {
            for _i in 0..MAX_COV2CLI_BURST {
                if !self.do_one_cov_read_cli_write(false) {
                    return;
                }
            }
            // If we reach here, there is still data left to be read. Rereg.
            rereg_queuer.rereg_cov_tcp(&self.session_id);
        }
    }
    // Returns true if you should continue calling this function.
    fn do_one_cov_read_cli_write(&mut self, force_reads: bool) -> bool
    {
        // Our buffering logic relies on writable events to keep things moving.
        // The writable events just call these do_X_read_Y_write functions. So,
        // if this was just an "is_empty()" check rather than a drain, you could
        // get freezes.
        if self.cli_pair.drain_send_buf() == BufStat::Nonempty {
            return false;
        }
        let mut buf = [0; 16*1024];
        let bytes_read = match self.cov.read(&mut buf[2..]) {
            ReadStat::GotData(n) => n,
            ReadStat::WouldBlock => 0,
            ReadStat::CleanShutdown => {
                self.send_cli_shutdown_msg();
                self.cli_pair.half_close();
                0 },
            ReadStat::Error => {
                self.end_whole_session_error(SessionError::CovertStream);
                0 }
        };
        if bytes_read <= 0 {
            return false;
        }

        protocol_sta2cli::write_data_tl_hdr(&mut buf, bytes_read);

        // Buffer stall sanity check: safe because either the write completes
        // (so we keep reading), or else the write buffers, and so a writeable
        // will eventually fire.
        let status = self.cli_pair.write(&buf[0..bytes_read+2]);
        match status {
            WriteStat::Buffered => {
                self.cov2cli_bytes_tot += bytes_read;
                return force_reads; },
            WriteStat::Error => {
                self.end_whole_session_error(SessionError::ClientStream);
                return false; },
            WriteStat::Complete => {
                self.cov2cli_bytes_tot += bytes_read;
                return true; }
        }
    }

    // Moves some data in the client->covert direction.
    pub fn cli_read_cov_write(&mut self, rereg_queuer: &mut ReregQueuer,
                              must_do_all_reads_now: bool)
    {
        if must_do_all_reads_now {
            while self.do_one_cli_read_cov_write(true) {}
        } else {
            for _i in 0..MAX_CLI2COV_BURST {
                if !self.do_one_cli_read_cov_write(false) {
                    return;
                }
            }
            // If we reach here, there is still data left to be read. Rereg.
            rereg_queuer.rereg_cli(&self.session_id);
        }
    }
    // Returns true if you should continue calling this function.
    // read_whole_cli_msg() selects either the traditional or upload-only stream
    // to read from based on which is currently the active uploader. It handles
    // verifying ACQUIRE if a YIELD just previously happened.
    // (process_cli2sta_proto() is what processes and effects the YIELD).
    fn do_one_cli_read_cov_write(&mut self, force_reads: bool) -> bool
    {
        // Our buffering logic relies on writable events to keep things moving.
        // The writable events just call these do_X_read_Y_write functions. So,
        // if this was just an "is_empty()" check rather than a drain, you could
        // get freezes.
        if self.cov.drain_send_buf() == BufStat::Nonempty {
            // Buffer stall sanity check: cov buffer non-empty means a cov
            // write WOULDBLOCKed, so a writeable event should be coming.
            return false;
        }
        let mut recvd = [0; 32*1024];
        let r = {
            let res = self.cli_pair.read_whole_cli_msg(&mut recvd);
            if let Ok(stuff) = res {
                stuff
            } else { // is_err(), so err().unwrap() is ok.
                self.end_whole_session_error(res.err().unwrap());
                return false;
            }
        };
        if !r.any_bytes_read {
            // Buffer stall sanity check: either we're shutting down or it's a
            // WOULDBLOCK, in which case we can expect a readable.
            return false;
        }
        if r.msg_size_in_buf > 0 || r.asmbld_msg.is_some() {
            // data should be in at most one of recvd / the returned Vec.
            if r.msg_size_in_buf > 0 && r.asmbld_msg.is_some() {
                error!("Have both one-shot and assembled data. Shouldn't \
                        happen. Session {} erroring out.", self.session_id);
                self.end_whole_session_error(SessionError::StationInternal);
                return false;
            }
            let (status, sent_len) =
                if r.msg_size_in_buf > 0 {
                    (self.cov.write(&recvd[0..r.msg_size_in_buf]),
                     r.msg_size_in_buf)
                } else if let Some(asmbld) = r.asmbld_msg {
                    let ref asmbld_slice = asmbld.as_slice();
                    (self.cov.write(asmbld_slice), asmbld_slice.len())
                } else {
                    error!("wait what? neither r.msg_size_in_buf>0 nor
                            asmbld_date.is_some. Session {} erroring out.",
                            self.session_id);
                    self.end_whole_session_error(SessionError::StationInternal);
                    return false;
                };
            match status {
                WriteStat::Buffered => {
                    self.cli2cov_bytes_tot += sent_len;
                    return force_reads; },
                WriteStat::Error => {
                    self.end_whole_session_error(SessionError::CovertStream);
                    return false; },
                WriteStat::Complete => {
                    self.cli2cov_bytes_tot += sent_len;
                    return true; }
            }
            // Buffer stall sanity check: safe because either the write
            // completes (so we keep reading), or else the write buffers, and so
            // a writeable will eventually fire. (Or err ends the session).
        }
        if let Some(proto) = r.proto {
            self.process_cli2sta_proto(proto);
            // Buffer stall sanity check: always return true => always keep
            // reading => no stall.
            return true;
        }
        // If we reach here, it should mean that some bytes were read, but a
        // message was not completed; more to come.
        return true;
    }
    // Consume a raw TCP packet, if our DirectionPair currently has an
    // upload-only component looking for such raw packets.
    // Returns false if FlowTracker should stop tracking this packet's flow.
    pub fn consume_tcp_pkt(&mut self, tcp_pkt: &TcpPacket) -> bool
    {
        self.cli_pair.consume_tcp_pkt(tcp_pkt)
    }
    pub fn process_cli2sta_proto(&mut self, proto: ClientToStation)
    {
        let cli_conf = unsafe { & *c_api::c_get_global_cli_conf() };

        if !self.received_gen {
            report!("listgen {} {}", self.session_id,
                    proto.get_decoy_list_generation());
            self.received_gen = true;
        }

        // defaults to 0
        if proto.get_decoy_list_generation() < cli_conf.get_generation() {
            let mut sta2cli = protocol_sta2cli::make_simple_proto(
                S2C_Transition::S2C_NO_CHANGE);
            sta2cli.set_config_info(cli_conf.clone());
            let mut framed_proto =
                empty_proto_frame_with_len(sta2cli.compute_size() as usize);
            sta2cli.write_to_vec(&mut framed_proto)
                   .unwrap_or_else(|e|{error!("writing sta2cli body: {}", e);});
            debug!("About to write a {}-byte ClientConf", framed_proto.len());
            if !self.nonfreezy_cli_write(framed_proto.as_slice()) {
                error!("Couldn't send ClientConf proto! Bailing on {}",
                       self.session_id);
                self.end_whole_session_error(SessionError::ClientStream);
            }
        }

        // Empty field defaults to NO_CHANGE
        match proto.get_state_transition() {
        C2S_Transition::C2S_NO_CHANGE => {},
        C2S_Transition::C2S_EXPECT_RECONNECT =>
            self.expect_bidi_reconnect = true,
        C2S_Transition::C2S_ACQUIRE_UPLOAD =>
            warn!("Got C2S_ACQUIRE_UPLOAD outside of \
                   DirectionPair::do_switchover! Session {}", self.session_id),
        C2S_Transition::C2S_EXPECT_UPLOADONLY_RECONN =>
            self.expect_uploader_reconnect = true,
        C2S_Transition::C2S_SESSION_CLOSE => {
            self.cov.half_close();
            // TODO HACK don't want to be treating a CLOSE message as also
            // a hangup of the underlying stream, but... it fits with how
            // the client currently works, and guarantees proper shutdown.
            if self.cli_pair.bidi_is_active_uploader {
                self.handle_cli_bidi_hup();
            } else {
                self.handle_cli_uploader_hup();
            }
        },
        C2S_Transition::C2S_YIELD_UPLOAD =>
            if let Err(e) =
               self.cli_pair.notice_uploader_yield(proto.get_upload_sync())
            {
                self.end_whole_session_error(e);
            },
        C2S_Transition::C2S_ERROR =>
            self.end_whole_session_error(SessionError::ClientReported),
        }

        for failed in proto.get_failed_decoys() {
            c_api::c_add_decoy_failure(failed);
        }
    }
}

impl Drop for TapdanceSession
{
    fn drop(&mut self)
    {
        info!("delsession {} {} {}", self.session_id,
               self.cov2cli_bytes_tot, self.cli2cov_bytes_tot);
    }
}















#[cfg(test)]
mod tests {

use protobuf;
use signalling::ClientToStation;
use session_id::SessionId;

#[test]
fn format_failed_decoys()
{
    let session_id = SessionId::new(&[255,255,255,255,255,255,255,255,
                                      255,255,255,255,255,255,255,255]);
    let mut msg1 = ClientToStation::new();
    msg1.set_protocol_version(123);
    assert_eq!(0, msg1.get_failed_decoys().len());

    let mut msg2 = ClientToStation::new();
    msg2.set_protocol_version(123);
    *msg2.mut_failed_decoys().push_default() = "1.2.3.4".to_string();
    let would_report2 = format!("decoysfailed {} {}", session_id,
                                msg2.get_failed_decoys().join(" "));
    assert_eq!("decoysfailed ffffffffffffffffffffffffffffffff 1.2.3.4",
               would_report2);

    let mut msg3 = ClientToStation::new();
    msg3.set_protocol_version(123);
    *msg3.mut_failed_decoys().push_default() = "5.6.7.8".to_string();
    *msg3.mut_failed_decoys().push_default() = "9.10.11.12".to_string();
    let would_report3 = format!("decoysfailed {} {}", session_id,
                                msg3.get_failed_decoys().join(" "));
    assert_eq!("decoysfailed ffffffffffffffffffffffffffffffff 5.6.7.8 \
                9.10.11.12", would_report3);

    let mut msg4 = ClientToStation::new();
    msg4.set_protocol_version(123);
    *msg4.mut_failed_decoys().push_default() = "1.1.1.1".to_string();
    *msg4.mut_failed_decoys().push_default() = "22.22.22.22".to_string();
    *msg4.mut_failed_decoys().push_default() = "233.233.233.233".to_string();
    let would_report4 = format!("decoysfailed {} {}", session_id,
                                msg4.get_failed_decoys().join(" "));
    assert_eq!("decoysfailed ffffffffffffffffffffffffffffffff \
                1.1.1.1 22.22.22.22 233.233.233.233", would_report4);
}

} // mod tests


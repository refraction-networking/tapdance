use protobuf::Message;

use c_api;
use protocol_sta2cli;
use protocol_sta2cli::empty_proto_frame_with_len;
use session_error::SessionError;
use signalling::{ClientToStation, C2S_Transition, S2C_Transition};
use tapdance_session::TapdanceSession;

// TODO at this point it should probably just go back into tapdance_session.rs

impl TapdanceSession
{
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
            }},
        C2S_Transition::C2S_YIELD_UPLOAD =>
            if let Err(e) = self.cli_pair.do_yield(proto.get_upload_sync()) {
                self.end_whole_session_error(e);},
        C2S_Transition::C2S_ERROR =>
            self.end_whole_session_error(SessionError::ClientReported),
        }

        for failed in proto.get_failed_decoys() {
            c_api::c_add_decoy_failure(failed);
        }
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

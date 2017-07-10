use mio::{Evented, Poll, PollOpt};
use pnet::packet::tcp::TcpPacket;

use bufferable_ssl::BufferableSSL;
use buffered_tunnel::BufferedTunnel;
use evented_ssl_eavesdropper::EventedSSLEavesdropper;
use protocol_outer_framing::OuterFrameMsgAssembler;
use session_error::SessionError;
use signalling::{ClientToStation, C2S_Transition};
use stream_traits::{StreamReceiver, BufStat, ReadStat, ShutStat, WriteStat};
use token_map::UniqTok;
use util;

pub struct DirectionPair
{
    // The traditional TapDance forged TLS stream. Bidirectional.
    bidi: BufferedTunnel<BufferableSSL>,
    // The upload-only eavesdropped TLS stream.
    uploader: Option<EventedSSLEavesdropper>,
    uploader_tok: Option<UniqTok>,
    uploader_count: usize,
    // Assembler for the current active uploader.
    assembler: OuterFrameMsgAssembler,
    pub bidi_is_active_uploader: bool,
    sorry_no_uploader_right_now: BlockedStreamReceiver,
    // The value specified in a recent YIELD proto. We expect the client's next
    // message to be an ACQUIRE proto, containing this value.
    yield_sync_val: Option<u64>,
}
// For when we are using EventedSSLEavesdroppers, but currently don't have one.
// Its job is to just say "nope sorry blocked".
struct BlockedStreamReceiver;
impl StreamReceiver for BlockedStreamReceiver
{
    #[allow(unused_variables)]
    fn read(&mut self, buf: &mut [u8]) -> ReadStat { ReadStat::WouldBlock }
}

enum MsgRead { Complete, Partial, WouldBlock }

impl DirectionPair
{
    pub fn do_rereg(&self, bidi_poll: &Poll, upl_poll: &Poll)
    {
        if let Some(tok) = self.bidi.peek_tok() {
            self.bidi.reregister(bidi_poll, tok,
                                 util::all_unix_events(), PollOpt::edge())
                .unwrap_or_else(|e|{warn!("bidi rereg err: {}", e)});
        }

        let evs = if self.bidi_is_active_uploader { util::hup_and_error() }
                  else                            { util::all_but_writable() };
        if let Some(ref tok) = self.uploader_tok {
            if let Some(ref upl) = self.uploader {
                upl.reregister(upl_poll, tok.val(), evs, PollOpt::edge())
                   .unwrap_or_else(|e|{warn!("upload-only rereg err: {}", e)});
            }
        }
    }

    // Returns a full message (if available) from the active uploader stream.
    // Handles the switch (verifies ACQUIRE) if there was previously a YIELD.
    // (process_cli2sta_proto() is what processes and effects the YIELD).
    //
    // Return values are:
    // 1) any_bytes_read (i.e. raw from the stream. 0 => shutdown or blocking).
    // 2) num_bytes_recvd_for_complete_data_msg (i.e. the first this many bytes
    //    of data_buf are filled with good data)
    // 3) a data message that was assembled. It's in here rather than written
    //    into data_buf for purely plumbing reasons.
    // 4) maybe_a_proto
    pub fn read_whole_cli_msg(&mut self, data_buf: &mut [u8])
    -> Result<(bool, usize, Option<Vec<u8>>, Option<ClientToStation>),
              SessionError>
    {
        if let Some(sync_val) = self.yield_sync_val {
            let r = self.do_switchover(data_buf, sync_val);
            if let Ok(status) = r {
                match status {
                    MsgRead::Complete => {},
                    MsgRead::Partial => return Ok((true, 0, None, None)),
                    MsgRead::WouldBlock => return Ok((false, 0, None, None))
                }
            }
            else if let Err(e) = r {
                return Err(e);
            }
        }

        if self.bidi_is_active_uploader {
            return self.assembler.read_whole_cli_msg(data_buf, &mut self.bidi);
        } else if let Some(ref mut rdr) = self.uploader {
            return self.assembler.read_whole_cli_msg(data_buf, rdr);
        } else {
            return self.assembler.read_whole_cli_msg(
                data_buf, &mut self.sorry_no_uploader_right_now);
        };
    }

    // sync_val should be yield_sync_val's (former) contents.
    // Ok(MsgRead) is whether to keep going (Complete), return with "partial
    // read", (Partial), or return with "wouldblock" (WouldBlock)
    fn do_switchover(&mut self, data_buf: &mut [u8], sync_val: u64)
    -> Result<MsgRead, SessionError>
    {
        let res = if self.bidi_is_active_uploader {
            self.assembler.read_whole_cli_msg(data_buf, &mut self.bidi)
        } else if let Some(ref mut rdr) = self.uploader {
            self.assembler.read_whole_cli_msg(data_buf, rdr)
        } else {
            self.assembler.read_whole_cli_msg(
                data_buf, &mut self.sorry_no_uploader_right_now)
        };
        if let Ok((any_bytes, data_bytes, data_msg, maybe_proto)) = res {
            if data_bytes > 0 || data_msg.is_some() {
                error!("Client sent a data msg when we expected ACQUIRE");
                return Err(SessionError::ClientProtocol);
            } else if !any_bytes {
                return Ok(MsgRead::WouldBlock);
            } else if let Some(proto) = maybe_proto {
                if proto.get_state_transition() !=
                    C2S_Transition::C2S_ACQUIRE_UPLOAD ||
                    proto.get_upload_sync() != sync_val
                {
                    error!("Client's proto not ACQUIRE, or wrong upload_sync");
                    return Err(SessionError::ClientProtocol);
                }
            } else {
                return Ok(MsgRead::Partial);
            }
        }
        else if let Err(e) = res { // read_whole_cli_msg() returned Err
            return Err(e);
        }
        self.yield_sync_val = None;
        // That's it; the switch is already done, ACQUIRE just confirms it.
        Ok(MsgRead::Complete)
    }

    // TODO rename: this doesn't "do" the yield so much as notice it
    pub fn do_yield(&mut self, sync_val: u64) -> Result<(), SessionError>
    {
        if !self.assembler.is_fresh()
        {
            error!("YIELD happened while assembler was not fresh!");
            return Err(SessionError::StationInternal);
        }
        self.yield_sync_val = Some(sync_val);
        self.bidi_is_active_uploader = !self.bidi_is_active_uploader;

        // registrations will be updated appropriately because this function
        // is called by process_cli2sta_proto(), which is ultimately called by
        // cli_read_cov_write().

        Ok(())
    }

    pub fn new() -> DirectionPair
    {
        DirectionPair { bidi: BufferedTunnel::new(),
                        uploader: None,
                        uploader_tok: None,
                        uploader_count: 0,
                        bidi_is_active_uploader: true,
                        sorry_no_uploader_right_now: BlockedStreamReceiver,
                        assembler: OuterFrameMsgAssembler::new(),
                        yield_sync_val: None }
    }
    pub fn set_bidi(&mut self, new_stream: BufferableSSL, new_tok: UniqTok,
                    cli_ssl_poll: &Poll) -> bool
    {
        if self.bidi.stream_is_some() && self.bidi_is_active_uploader {
            // TODO if "expect_reconnect", probably it's fine to treat this as
            // an implicit close of the previous stream, and just replace it.
            error!("Trying to overwrite a bidi!");
            return false;
        }
        self.bidi.set_stream(new_stream);

        // Yes, interested in all events including readable even if bidi isn't
        // the active uploader. That's because of the annoying possibility of
        // SSL_write wanting a readable event before it can make progress. The
        // logic of "bidi readable should not cause a cli_read_cov_write when
        // bidi isn't active" is taken care of in ClientSSLDriver.
        let evs = util::all_unix_events();

        self.bidi.register(cli_ssl_poll, new_tok.val(), evs, PollOpt::edge())
                 .unwrap_or_else(|e|{error!("ssl_driver 1st reg: {}",e)});

        self.bidi.set_tok(new_tok);
        return true;
    }
    pub fn set_passive_uploader(&mut self, new_stream: EventedSSLEavesdropper,
                                new_tok: UniqTok, cli_psv_poll: &Poll) -> bool
    {
        if self.uploader.is_some() {
            // TODO if "expect_UPL_reconnect", probably it's fine to treat this
            // as an implicit close of the previous stream, and just replace it.
            error!("Trying to overwrite an upload-only!");
            return false;
        }
        let evs = if self.bidi_is_active_uploader { util::hup_and_error() }
                  else                            { util::all_but_writable() };
        new_stream.register(cli_psv_poll, new_tok.val(), evs,PollOpt::edge())
                  .unwrap_or_else(|e|{error!("psv_driver 1st reg: {}", e)});
        self.uploader_tok = Some(new_tok);
        self.uploader = Some(new_stream);
        self.uploader_count += 1;
        return true;
    }
    pub fn drop_passive_uploader(&mut self)
    {
        self.uploader = None;
        // No need to do anything about the token here; ClientPassiveDriver's
        // cleanup after event processing will get it (as well as remove it
        // from its tok2sess map).
    }
    // Returns false if FlowTracker should stop tracking this packet's flow.
    pub fn consume_tcp_pkt(&mut self, tcp_pkt: &TcpPacket) -> bool
    {
        // TODO TODO TODO DittoTap
        // for now, just pass it to self.cli_pair's uploader. eventually,
        // though, this function will direct it either to the split-dir
        // upload-only, OR to the dittoTap bidi (could be reader or writer!)
        if let Some(ref mut u) = self.uploader {
            u.consume_tcp_pkt(tcp_pkt)
        }
        else {false}
    }
    pub fn unclean_shutdown(&mut self)
    {
        self.bidi.unclean_shutdown();
        self.uploader = None;
    }
    // See BufferedTunnel::stream_count(). Returns (uploader_count, bidi_count).
    pub fn stream_count(&self) -> (usize, usize)
    {
        (self.uploader_count, self.bidi.stream_count())
    }
    pub fn take_bidi_tok(&mut self) -> Option<UniqTok>
    {
        self.bidi.take_tok()
    }
    pub fn take_upl_tok(&mut self) -> Option<UniqTok>
    {
        self.uploader_tok.take()
    }


    // Passthroughs to bidi (BufferedTunnel)
    pub fn half_closed(&self) -> bool { self.bidi.half_closed() }
    pub fn write(&mut self, data: &[u8]) -> WriteStat { self.bidi.write(data) }
    pub fn write_skipping_buffer(&mut self, data: &[u8]) -> WriteStat
    {
        self.bidi.write_skipping_buffer(data)
    }
    pub fn drain_send_buf(&mut self) -> BufStat { self.bidi.drain_send_buf() }
    pub fn half_close(&mut self) { self.bidi.half_close() }
    pub fn write_no_flush(&mut self, data: &[u8]) -> WriteStat
    {
        self.bidi.write_no_flush(data)
    }
    pub fn set_bidi_read_closed(&mut self) { self.bidi.set_read_closed() }
    pub fn bidi_clean_shutdown(&mut self) -> ShutStat
    {
        self.bidi.clean_shutdown()
    }
    pub fn bidi_read_wants_writable(&self) -> bool
    {
        self.bidi.read_wants_writable()
    }
    pub fn bidi_write_wants_readable(&self) -> bool
    {
        self.bidi.write_wants_readable()
    }
    pub fn bidi_stream_is_some(&self) -> bool { self.bidi.stream_is_some() }
    pub fn uploader_is_some(&self) -> bool { self.uploader.is_some() }
    pub fn bidi_rw_is_open(&self) -> (bool, bool) { self.bidi.rw_is_open() }
}

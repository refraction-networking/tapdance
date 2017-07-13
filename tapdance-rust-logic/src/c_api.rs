#![allow(non_snake_case)]

use std::collections::HashMap;
use std::os::raw::c_void;
use libc::size_t;

use signalling::ClientConf;

//HACKY_CFG_NO_TEST_BEGIN
#[link(name = "ssl")]
extern {
    fn SSL_read(ssl: *mut c_void, output: *mut u8, out_len: i32) -> i32;
    fn SSL_write(ssl: *mut c_void, input: *const u8, in_len: i32) -> i32;
    fn SSL_shutdown(ssl: *mut c_void) -> i32;
    fn SSL_get_error(ssl: *const c_void, ret: i32) -> i32;
    fn SSL_free(ssl: *mut c_void);
    fn ERR_clear_error();
    fn BIO_new(method: *mut c_void) -> *mut c_void;
    fn BIO_s_mem() -> *mut c_void;
    fn BIO_write(bio: *mut c_void, data: *const u8, data_len: i32) -> i32;
    fn BIO_free_all(bio: *mut c_void);
}

pub fn c_SSL_read(ssl: *mut c_void, output: &mut [u8])
-> Result<usize, i32>
{
    let read_res = unsafe {
        ERR_clear_error();
        SSL_read(ssl, output.as_mut_ptr(), output.len() as i32)
    };
    if read_res > 0 {
        Ok(read_res as usize)
    } else {
        Err(unsafe{SSL_get_error(ssl, read_res)})
    }
}
pub fn c_SSL_write(ssl: *mut c_void, input: &[u8])
-> Result<usize, i32>
{
    let write_res = unsafe {
        ERR_clear_error();
        SSL_write(ssl, input.as_ptr(), input.len() as i32)
    };
    if write_res > 0 {
        c_add_to_global_cli_download_count(write_res as u64);
        Ok(write_res as usize)
    } else {
        Err(unsafe{SSL_get_error(ssl, write_res)})
    }
}
// Returns Ok(true) if the shutdown is complete, Ok(false) if in progress,
// Err(SSLerr i32) for various reasons (including WOULDBLOCKs, i.e. in progress)
pub fn c_SSL_shutdown(ssl: *mut c_void)
-> Result<bool, i32>
{
    let res = unsafe {
        ERR_clear_error();
        SSL_shutdown(ssl)
    };
    if res == 1 { Ok(true) }
    else if res == 0 { Ok(false) }
    else { Err(unsafe{SSL_get_error(ssl, res)}) }
}
pub fn c_SSL_free(ssl: *mut c_void) { unsafe { SSL_free(ssl) }}
pub fn c_ugh_ssl_err() { unsafe { ugh_ssl_err(); }}
pub fn c_ERR_clear_error() { unsafe { ERR_clear_error(); }}
pub fn c_new_membio() -> *mut c_void { unsafe { BIO_new(BIO_s_mem()) }}
pub fn c_BIO_free_all(bio: *mut c_void) { unsafe { BIO_free_all(bio); } }
pub fn c_BIO_write(bio: *mut c_void, data: &[u8]) -> i32
{
    unsafe { BIO_write(bio, data.as_ptr(), data.len() as i32) }
}

//#[cfg(not(test))]
#[link(name = "tapdance")]
extern {
    // Creates a forge socket with the given TCP parameters,
    // and attaches an SSL object to it with the given TLS params.
    // Returned ptr is the SSL object. The underlying (forged) TCP fd is written
    // to forged_fd_out.
    //
    // local_ip, local_port, remote_ip, remote_port should all be net-order.
    // The rest are host-order.
    fn make_forged_tls(local_ip: u32, local_port: u16,
                       remote_ip: u32, remote_port: u16,
                       tcp_seq: u32, tcp_ack: u32,
                       cli_tcp_win: u16, cli_advertised_wscale: u8,
                       tcp_mss: u16,
                       tcp_ts: u32, tcp_ts_ecr: u32,
                       master_secret: *const u8, master_secret_len: usize,
                       cipher_suite: u16, client_random: *const u8,
                       server_random: *const u8,
                       app_data: *const u8, app_data_len: usize,
                       forged_fd_out: *mut i32) -> *mut c_void;
    // Forges an SSL object with mem BIOs (feed packets into the "input from
    // the network" BIO yourself), rather than socket BIOs.
    fn make_forged_memory_tls(
        master_secret: *const u8, master_secret_len: usize,
        cipher_suite: u16, client_random: *const u8, server_random: *const u8,
        app_data: *const u8, app_data_len: usize,
        from_cli_membio: *mut c_void, unused_to_cli_membio: *mut c_void)
    -> *mut c_void;

    // For the station; given a tag, return the payload.
    // Currently, out must support at least 144 bytes.
    // Supposed to return number of bytes written into out, I think?
    // It's hardcoded to 176 though...
    fn get_payload_from_tag(station_privkey: *const u8,
						   stego_payload: *mut u8,
                           stego_len: size_t,
						   out: *mut u8,
						   out_len: size_t) -> size_t;

    fn get_cpu_time(usr_secs: *mut i64, usr_micros: *mut i64, 
                    sys_secs: *mut i64, sys_micros: *mut i64);

    fn ugh_ssl_err();

    fn open_reporter(fname: *const u8); // const char *
    fn write_reporter(msg: *const u8, len: size_t);

    // Send a TCP RST to daddr:dport, spoofed from saddr:sport. seq must be the
    // last ACK val observed from the targeted host, so it won't ignore the ACK.
    // saddr, daddr, sport, dport, seq must all be network order. HOWEVER,
    // note that c_tcp_send_rst_pkt() does to_be() on all of these, so
    // give c_tcp_send_rst_pkt() (but NOT this fn) host-order arguments!
    fn tcp_send_rst_pkt(saddr: u32, daddr: u32,
                        sport: u16, dport: u16, seq: u32);
    fn get_global_cli_conf() -> *const c_void;
    fn add_to_global_cli_download_count(input: u64);
    fn reset_global_cli_download_count();
    fn get_global_cli_download_count() -> u64;
    fn get_mut_global_failure_map() -> *mut c_void;
}

// local_ip, local_port, remote_ip, remote_port should all be net-order.
// The rest are host-order.
pub fn c_make_forged_tls(
    local_ip: u32, local_port: u16, remote_ip: u32, remote_port: u16,
    tcp_seq: u32, tcp_ack: u32, cli_tcp_win: u16,
    cli_advertised_wscale: u8, tcp_mss: u16, tcp_ts: u32, tcp_ts_ecr: u32,
    master_secret: &[u8], cipher_suite: u16,
    client_random: &[u8], server_random: &[u8],
    app_data: &[u8], forged_fd_out: *mut i32)
-> *mut c_void
{
	unsafe {
		make_forged_tls(
            local_ip, local_port, remote_ip, remote_port, tcp_seq, tcp_ack,
            cli_tcp_win, cli_advertised_wscale, tcp_mss, tcp_ts, tcp_ts_ecr,
            master_secret.as_ptr(), master_secret.len(), cipher_suite,
            client_random.as_ptr(), server_random.as_ptr(),
            app_data.as_ptr(), app_data.len(), forged_fd_out)
	}
}
pub fn c_make_forged_memory_tls(master_secret: &[u8], cipher_suite: u16,
    client_random: &[u8], server_random: &[u8], app_data: &[u8],
    from_cli_membio: *mut c_void, unused_to_cli_membio: *mut c_void)
-> *mut c_void
{
    unsafe {
        make_forged_memory_tls(
            master_secret.as_ptr(), master_secret.len(), cipher_suite,
            client_random.as_ptr(), server_random.as_ptr(),
            app_data.as_ptr(), app_data.len(),
            from_cli_membio, unused_to_cli_membio)
    }
}

pub fn c_get_payload_from_tag(station_privkey: &[u8],
                              stego_payload: &mut [u8],
                              out: &mut [u8], out_len: size_t) -> size_t
{
	unsafe {
        get_payload_from_tag(station_privkey.as_ptr(),
                             stego_payload.as_mut_ptr(), stego_payload.len(),
						     out.as_mut_ptr(), out_len) }
}

pub fn c_get_cpu_time() -> (i64, i64, i64, i64)
{
    let mut usr_secs: i64 = 0;
    let mut usr_us: i64 = 0;
    let mut sys_secs: i64 = 0;
    let mut sys_us: i64 = 0;
    unsafe { get_cpu_time(&mut usr_secs as *mut i64, &mut usr_us as *mut i64,
                          &mut sys_secs as *mut i64, &mut sys_us as *mut i64); }
    (usr_secs, usr_us, sys_secs, sys_us)
}

pub fn c_open_reporter(fname: String)
{
    unsafe {
        open_reporter(fname.as_ptr()); }
}

pub fn c_write_reporter(msg: String)
{
    //let n =
    unsafe { write_reporter(msg.as_ptr(), msg.len()); }
}

// Arguments should all be host-order: this function does the conversion.
pub fn c_tcp_send_rst_pkt(saddr: u32, daddr: u32,
                          sport: u16, dport: u16, seq: u32)
{
    unsafe { tcp_send_rst_pkt(saddr.to_be(), daddr.to_be(),
                              sport.to_be(), dport.to_be(), seq.to_be()) }
}

pub fn c_get_global_cli_conf() -> *const ClientConf
{
    unsafe { get_global_cli_conf() as *const ClientConf }
}

pub fn c_add_to_global_cli_download_count(input: u64)
{
    unsafe { add_to_global_cli_download_count(input) }
}
pub fn c_reset_global_cli_download_count()
{
    unsafe { reset_global_cli_download_count() }
}
pub fn c_get_global_cli_download_count() -> u64
{
    unsafe { get_global_cli_download_count() }
}
pub fn c_add_decoy_failure(failed: &String)
{
    let mut fail_map = unsafe{ &mut *(get_mut_global_failure_map()
                                      as *mut HashMap<String, usize>) };
    let the_entry = fail_map.entry(failed.clone()).or_insert(0);
    *the_entry += 1;
}
pub unsafe fn get_global_failure_map_rawptr() -> *mut HashMap<String, usize>
{
    get_mut_global_failure_map() as *mut HashMap<String, usize>
}

//HACKY_CFG_NO_TEST_END*/













/*//HACKY_CFG_YES_TEST_BEGIN
fn SSL_read(ssl: *mut c_void, output: *mut u8, out_len: i32) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
fn SSL_write(ssl: *mut c_void, input: *const u8, in_len: i32) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
fn SSL_get_error(ssl: *const c_void, ret: i32) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
fn SSL_free(ssl: *mut c_void)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_read(ssl: *mut c_void, output: &mut [u8])
-> Result<usize, i32>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_write(ssl: *mut c_void, input: &[u8])
-> Result<usize, i32>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_shutdown(ssl: *mut c_void)
-> Result<bool, i32>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_free(ssl: *mut c_void)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_ugh_ssl_err()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_ERR_clear_error()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_new_membio()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_BIO_write(bio: *mut c_void, data: &[u8]) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_BIO_free_all(bio: *mut c_void)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_make_forged_tls(local_ip: u32, local_port: u16,
                         remote_ip: u32, remote_port: u16,
                         tcp_seq: u32, tcp_ack: u32,
                         cli_tcp_win: u16, cli_advertised_wscale: u8,
                         tcp_mss: u16, tcp_ts: u32, tcp_ts_ecr: u32,
                         master_secret: &[u8], cipher_suite: u16,
                         client_random: &[u8], server_random: &[u8],
                         app_data: &[u8], forged_fd_out: *mut i32)
-> *mut c_void
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_make_forged_memory_tls(master_secret: &[u8], cipher_suite: u16,
    client_random: &[u8], server_random: &[u8], app_data: &[u8],
    from_cli_membio: *mut c_void, unused_to_cli_membio: *mut c_void)
-> *mut c_void
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}


pub fn c_get_payload_from_tag(station_privkey: &[u8],
                                 stego_payload: &mut [u8],
                                 out: &mut [u8], out_len: size_t) -> size_t
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}

pub fn c_get_cpu_time() -> (i64, i64, i64, i64)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_open_reporter(fname: String)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_write_reporter(msg: String)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_tcp_send_rst_pkt(saddr: u32, daddr: u32,
                          sport: u16, dport: u16, seq: u32)
{panic!("c_tcp_send_rst_pkt({}) called", seq);}
pub fn c_get_global_cli_conf() -> *const ClientConf
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_add_to_global_cli_download_count(input: u64)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_add_decoy_failure(failed: &String)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn get_global_failure_map_rawptr() -> *mut HashMap<String, usize>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_reset_global_cli_download_count()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_get_global_cli_download_count() -> u64
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
//HACKY_CFG_YES_TEST_END*/

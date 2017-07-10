#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include "elligator2.h"


// Public functions, to be called from rust

// Creates a forge socket with the given TCP parameters, and attaches an SSL
// object to it with the given TLS params.
// Return value is an opaque pointer to an SSL object, which Rust passes when
// calling C's various SSL_*() functions.
// Also returns the (forged) TCP socket fd underlying the SSL object; that fd
// is stored at forged_fd_out.
//
// local_ip, local_port, remote_ip, remote_port should all be net-order.
// The rest are host-order.
void *make_forged_tls(uint32_t local_ip, uint16_t local_port,
                      uint32_t remote_ip, uint16_t remote_port,
                      uint32_t tcp_seq, uint32_t tcp_ack,
                      uint16_t cli_tcp_win, uint8_t cli_advertised_wscale,
                      uint16_t tcp_mss,
                      uint32_t tcp_ts, uint32_t tcp_ts_ecr,
                      uint8_t *master_secret, size_t master_secret_len,
                      uint16_t cipher_suite, uint8_t *client_random,
                      uint8_t *server_random,
                      uint8_t *app_data, size_t app_data_len,
                      int* forged_fd_out);
void* make_forged_memory_tls(uint8_t* master_secret, size_t master_secret_len,
                             uint16_t cipher_suite,
                             uint8_t* client_random, uint8_t* server_random,
                             uint8_t* app_data, size_t app_data_len,
                             BIO* from_cli_membio, BIO* unused_to_cli_membio);
void ugh_ssl_err();

void add_to_global_cli_download_count(uint64_t input);
void reset_global_cli_download_count();
uint64_t get_global_cli_download_count();
void* get_mut_global_failure_map();
const void* get_global_cli_conf();
void open_reporter(const char *fname);
size_t write_reporter(uint8_t *buf, size_t len);

void get_cpu_time(int64_t* usr_secs, int64_t* usr_micros, int64_t* sys_secs,
                  int64_t* sys_micros);

// Send a TCP RST to daddr:dport, spoofed from saddr:sport. seq must be the last
// ACK val observed from the targeted host, so that it won't ignore the ACK.
// saddr, daddr, sport, dport, seq must all be network order.
void tcp_send_rst_pkt(uint32_t saddr, uint32_t daddr,
                      uint16_t sport, uint16_t dport,
                      uint32_t seq);

// Private, called internally
SSL* get_ssl_obj(uint8_t *master_secret, size_t master_secret_len,
                 uint16_t cipher_suite, uint8_t *client_random,
                 uint8_t *server_random, int npn);

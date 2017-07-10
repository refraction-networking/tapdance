#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "forge_socket.h"

#include "tapdance.h"
#include "ssl_api.h"

// Fills in all but the src/dst ip/port and seq/ack numbers
// with some sane defaults
void default_state(struct tcp_state *st)
{
    if (st == NULL) {
        return;
    }
    memset(st, 0, sizeof(struct tcp_state));
    st->tstamp_ok = 0;
    st->sack_ok = 1;
    st->wscale_ok = 0;
    st->ecn_ok = 0;
    st->snd_wscale = 0;
    st->rcv_wscale = 0;
    st->snd_wnd = 0x1000;
    st->rcv_wnd = 0x1000;
    st->mss_clamp = 1400; // We overwrite this with the MSS specified in the
                          // SYN options. This is just a conservative default.
    //make sure you set snd_una = seq (TODO: fix this in module)
}


int forge_socket_set_state(int sock, struct tcp_state *st)
{
    struct sockaddr_in sin;
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = st->src_ip;
    sin.sin_port        = st->sport;

    st->snd_una = st->seq;

    int value = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }

    if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)) < 0) {
        perror("setsockopt IP_TRANSPARENT");
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_STATE, st, sizeof(struct tcp_state)) < 0) {
        perror("setsockopt TCP_STATE");
        return -1;
    }

    return 0;
}

// local_ip, local_port, remote_ip, remote_port should all be net-order.
// The rest are host-order.
int make_forged_socket(uint32_t local_ip, uint16_t local_port,
                       uint32_t remote_ip, uint16_t remote_port,
                       uint32_t tcp_seq, uint32_t tcp_ack,
                       uint16_t cli_tcp_win, uint8_t cli_advertised_wscale,
                       uint16_t tcp_mss,
                       uint32_t tcp_ts, uint32_t tcp_ts_ecr)
{
    // Setup forge_socket state
    struct tcp_state state;
    default_state(&state);
    int forged_sock = socket(AF_INET, SOCK_FORGE, 0);
    if (forged_sock == -1) {
        perror("socket for forge_socket");
        return -1;
    }
    state.src_ip = local_ip;
    state.dst_ip = remote_ip;
    state.sport  = local_port;
    state.dport  = remote_port;
    state.seq    = tcp_seq;
    state.ack    = tcp_ack;

    // Window scaling: *Ideally*, we would like to tell forge_socket the correct
    // values for both snd_wscale and rcv_wscale. snd_wscale is the scaling
    // factor to be applied to the client's window advertisements; it was
    // specified back in the client's SYN. rcv_wscale is for the decoy (and our
    // spoofed stuff); it was specified back in the decoy's SYNACK.
    //
    // Getting snd_wscale right is necessary for correctness: we need to know
    // what size flow control window the client is actually advertising to us.
    // Getting rcv_wscale right is useful for camouflage: it would look weird
    // if the "decoy" was suddenly advertising a window 2x, 4x, 8x, 16x, etc
    // less/more than before. (Ideally we would also copy the decoy's current
    // unshifted window value, for a totally seamless switch over to spoofing).
    //
    // The station can get snd_wscale easily enough, since it sees the client's
    // SYN. rcv_wscale is much harder: we would need the client to get it and
    // communicate it to us in the tag. I would guess Go TCP does not give you
    // access to such low level info. So, 'TODO' but maybe never.
    state.wscale_ok = 1;

    // This should be what the client last advertised its window to be.
    state.snd_wnd = cli_tcp_win; // gotten from the tagged packet's TCP header
    state.snd_wscale = cli_advertised_wscale; // gotten from the client's SYN

    // The decoy's current window advertisement (TODO learn via client tag?)
    state.rcv_wnd = 470;  // << state.rcv_wscale to get true value
    state.rcv_wscale = 7; // TODO: need decoy's SYN-ACK (learn via client tag?)

    // TCP timestamps
    state.tstamp_ok = (tcp_ts == 0) ? 0 : 1;
    state.ts_recent = tcp_ts;
    state.ts_val = tcp_ts_ecr + 1;

    // Max segment size client can receive. Client advertises in SYN (mss opt).
    state.mss_clamp = tcp_mss;

    if (forge_socket_set_state(forged_sock, &state) != 0) {
        fprintf(stderr, "set_sock_state failed!\n");
        return -1;
    }
    return forged_sock;
}


SSL *get_ssl_obj_and_decrypt(uint8_t *master_secret, size_t master_secret_len,
                            uint16_t cipher_suite,
                            uint8_t *server_random, uint8_t *client_random,
                            int npn_negotiated,
                            uint8_t *app_data, size_t app_data_len)
{
    SSL *ssl_obj = NULL;
    // Setup SSL object
    ssl_obj = get_ssl_obj(master_secret, master_secret_len, cipher_suite,
                          server_random, client_random, npn_negotiated);
    if (ssl_obj == NULL) {
        fprintf(stderr, "bad ssl obj from get_ssl_obj()\n");
        return NULL;
    }

    // The caller is supposed to pass the entire first TLS app data record in
    // 'app_data'. Decrypting it with our newly cobbled-together SSL object
    // 1) confirms that we cobbled the SSL object together correctly
    // 2) advances the SSL object's state to after that first app data (where
    //    it should be, to be able to decrypt the client's next data record).
    char* req_plaintext;
    int req_len = ssl_decrypt(ssl_obj, app_data, app_data_len, &req_plaintext);
    if (req_len < 0) {
        SSL_free(ssl_obj);
        free(req_plaintext);
        return NULL;
    }

    free(req_plaintext);
    return ssl_obj;
}

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
                      int* forged_fd_out)
{
    // Try to get the object without NPN support
    SSL *ssl_obj = get_ssl_obj_and_decrypt(master_secret, master_secret_len,
                                           cipher_suite,
                                           server_random, client_random,
                                           0, app_data, app_data_len);
    if (!ssl_obj) {
        // If that doesn't work, try again, with NPN support
        ssl_obj = get_ssl_obj_and_decrypt(master_secret, master_secret_len,
                                          cipher_suite,
                                          server_random, client_random, 1,
                                          app_data, app_data_len);
    }
    if (!ssl_obj) {
        // And if THAT doesn't work, then give up, go home.
        return NULL;
    }
    int forged_sock = make_forged_socket(local_ip, local_port,
                                         remote_ip, remote_port,
                                         tcp_seq, tcp_ack,
                                         cli_tcp_win, cli_advertised_wscale,
                                         tcp_mss, tcp_ts, tcp_ts_ecr);
    if(forged_sock < 0)
    {
        SSL_free(ssl_obj);
        return NULL;
    }

    // Make forged_sock non-blocking
    int socket_flags;
    if (-1 == (socket_flags = fcntl(forged_sock, F_GETFL, 0)))
        socket_flags = 0;
    fcntl(forged_sock, F_SETFL, socket_flags | O_NONBLOCK);

    // Switch our hacked-together SSL object over to using the forged TCP flow.
    BIO* bio = BIO_new_socket(forged_sock, BIO_CLOSE);
    SSL_set_bio(ssl_obj, bio, bio);

    if(forged_fd_out)
        *forged_fd_out = forged_sock;
    return ssl_obj;
}

void* make_forged_memory_tls(uint8_t* master_secret, size_t master_secret_len,
                             uint16_t cipher_suite,
                             uint8_t* client_random, uint8_t* server_random,
                             uint8_t* app_data, size_t app_data_len,
                             BIO* from_cli_membio, BIO* unused_to_cli_membio)
{
    // Try to get the object without NPN support
    SSL* ssl_obj = get_ssl_obj_and_decrypt(master_secret, master_secret_len,
                                           cipher_suite,
                                           server_random, client_random,
                                           0, app_data, app_data_len);
    if (!ssl_obj) { // If that doesn't work, try again, with NPN support
        ssl_obj = get_ssl_obj_and_decrypt(master_secret, master_secret_len,
                                          cipher_suite,
                                          server_random, client_random, 1,
                                          app_data, app_data_len);
    }
    if (!ssl_obj) // And if THAT doesn't work, then give up, go home.
        return NULL;

    // Have our hacked-together SSL object use the provided memBIOs.
    SSL_set_bio(ssl_obj, from_cli_membio, unused_to_cli_membio);

    return ssl_obj;
}

void ugh_ssl_err()
{
    ERR_print_errors_fp(stderr);
}

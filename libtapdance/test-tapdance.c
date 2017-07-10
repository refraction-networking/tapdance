

#include <unistd.h>
#include "tapdance.h"
#include <event2/event.h>

void decode_hex(uint8_t *dest, char *hex)
{
    size_t len = strlen(hex) / 2;
    size_t i;
    uint8_t tmp[3];
    tmp[2] = '\x00';
    for (i=0; i<len; i++) {
        memcpy(tmp, &hex[i*2], 2);
        dest[i] = strtol(tmp, NULL, 16);
    }
}


int main() {

    struct event_base *base = event_base_new();

    uint32_t local_ip = inet_addr("127.0.0.1");
    uint32_t remote_ip = inet_addr("127.0.0.1");
    uint16_t local_port = htons(4433);
    uint16_t remote_port = htons(12345);
    uint32_t tcp_seq = htonl(0xdeadbeef), tcp_ack = htonl(0xaabbccdd);
    uint16_t tcp_win = 16384;
    uint32_t tcp_ts = 0;
    uint32_t tcp_ts_ecr = 0;
    size_t master_secret_len = 48;
    uint16_t cipher_suite = htons(0xc02f);  // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    uint8_t master_secret[48];
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t app_data[325];
    size_t app_data_len = 325;
    decode_hex(app_data, "1703030140b766b8408e4981e68913f51b8c3ebce5155912b0d6a67e945670ef406f9671ec6272c803f9a5cedb59cca5c7a03c51545b2464f6267b4c483fd50781a4741b37e29b3eeac66a1156e9b25084e226acac4c15277f8fa6f1560c7e0440b5be2de08af103d3925aa454a7d6e33f320871952948c7f106367f3b7d7aa7915270c3a00a039ec1f4a90e16da2a44d16cc0e4d6d1035495ef6473ef9a871c9d46708e819a8dd8b88a3d079498f8b5f525478e4e2f6703baafee5d9e8848719c4d8dc2c51466efaf1ff1231deace63b18ad0a190ce5ea3aed58fe6e9002407ef88895589aa7a8c8ae0d28424931fbbd817c6ec55a7caff4d31e03ff0634b6c5b86f03d37d88d8142ddc99abe8759fc410557678b5b80eb36e2502f8883d3c36b316df78cc96c143b2b2a59916d93943475597938782b8bbddb60724311cf236bb579590c");
    decode_hex(master_secret, "4bff4fe6f863736a7f7ffca88978260c1f4f38acf2460a7f90904b2ac3442f7afa92d3af905e2acc0262744d659d9d73");
    decode_hex(client_random, "58fdefcf5dcc1f8bab464a6b99309382f5d3fe93f5dc2b54c6098ec32fe9b3f4");
    decode_hex(server_random, "578945fa153a72d920caf85bce973aeba21473c9d72b9b4b704aaba1b7efe467");


    void *ptr = tapdance_get_conn(base,
                       local_ip, local_port, remote_ip, remote_port,
                       tcp_seq, tcp_ack,
                       tcp_win, // ... other TCP options?
                       tcp_ts, tcp_ts_ecr,
                       master_secret, master_secret_len,
                       cipher_suite, client_random,
                       server_random,
                       app_data, app_data_len);

    printf("%p\n", ptr);

}

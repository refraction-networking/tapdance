#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <stdint.h>
#include "elligator2.h"
#include <sys/time.h>
#include <getopt.h>


// TODO: make curve25519-donna.h
typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *, const u8 *, const u8 *);

float get_ms_diff(struct timeval *start, struct timeval *end)
{
    return (1000.0*(end->tv_sec - start->tv_sec)) + ((float)(end->tv_usec - start->tv_usec)) / 1000.0;
}



int main(int argc, char *argv[])
{
    unsigned char base_point[32] = {9};     // G

    unsigned char secret_key[32];   // d
    uint8_t *stego_payload = NULL;
    size_t stego_len = 0;
    uint8_t point[32];
    int has_point = 0;

    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"key",   optional_argument, 0, 'k'},
        {"tag", optional_argument, 0, 't'},
        {"point", optional_argument, 0, 'p'},
        {0, 0, 0, 0}
    };
    FILE *f;
    int i;
    while (1) {
        c = getopt_long(argc, argv, "k:t:p:", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 'k':
            f = fopen(optarg, "r");
            if (!f) {
                printf("could not open privkey");
                return 1;
            }
            size_t len = fread(secret_key, sizeof(secret_key), 1, f);
            if (len != 1) {
                printf("failed to load privkey: read only %d bytes\n", len);
                return 1;
            }
            fclose(f);
            break;
        case 't':
            // optarg is a hex representation of a stego payload
            // decode payload
            stego_len = strlen(optarg) / 2;
            stego_payload = malloc(stego_len);
            for (i=0; i<stego_len; i++) {
                uint8_t tmp[3];
                memcpy(tmp, &optarg[i*2], 2);
                stego_payload[i] = strtol(tmp, NULL, 16);
            }
            break;
        case 'p':
            // optarg is a hex representation of a point to decode
            has_point = 1;
            uint8_t tmp[3];
            tmp[2] = '\x00';
            for (i=0; i<strlen(optarg); i++) {
                memcpy(tmp, &optarg[i*2], 2);
                point[i] = strtol(tmp, NULL, 16);
            }
            break;
        }
    }

    if (has_point) {
        uint8_t out[32];
        int res = decode(out, point);
        printf("Decoded point %d: ", res);
        for (i=0; i<32; i++) {
            printf("%02x", out[i]);
        }
        printf("\n");
    }


    /*
    station_secret[0] &= 248;
    station_secret[31] &= 127;
    station_secret[31] |= 64;
    */
    if (stego_payload) {
        unsigned char payload[200];
        size_t len = get_payload_from_tag(secret_key, stego_payload, stego_len, payload, sizeof(payload));

        printf("Decoded/decrypted tag to %zu-byte payload:\n", len);
        for (i=0; i<len; i++) {
            printf("%02x", payload[i]);
        }
        printf("\n");

    }



    return 0;
}


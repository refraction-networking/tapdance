#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "elligator2.h"
#include <gmp.h>

#include "loadkey.h"

// TODO: make curve25519-donna.h
typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *, const u8 *, const u8 *);

size_t get_rand_str(unsigned char *randout, size_t len)
{
    FILE *f = fopen("/dev/urandom", "r");
    if (!f) {
        return 0;
    }
    size_t r = fread(randout, 1, len, f);
    fclose(f);
    return r;
}

static void fatal_error(const char *progname, const char *err)
{
    printf("%s: error: %s\n", progname, err);
    exit(1);
}

static void usage(const char *progname)
{
    printf("Usage: %s\n", progname);
    printf("\n");
    printf("    Chooses a random 32-byte private key, and then overwrites\n");
    printf("    ./pubkey and ./privkey with new public and private keys.\n");
}

int main(int argc, char **argv)
{
    unsigned char base_point[TD_KEYLEN_BYTES] = {9};	// G
    int rc;

    // ================
    // Station specific
    // ================
    unsigned char station_secret[TD_KEYLEN_BYTES];   // d
    unsigned char station_public[TD_KEYLEN_BYTES];   // P = dG

    if (argc != 1) {
        usage(argv[0]);
        exit(1);
    }

    printf("Creating private station key...\n");
    rc = get_rand_str(station_secret, sizeof(station_secret));
    if (rc != sizeof(station_secret)) {
        fatal_error(argv[0], "could not create station key");
    }

    printf("Generating client public key...\n");
    station_secret[0] &= 248;
    station_secret[31] &= 127;
    station_secret[31] |= 64;

    // compute P = dG
    //
    // Note: the return value of curve25519_donna has no meaning
    curve25519_donna(station_public, station_secret, base_point);

    printf("Writing key files...\n");

    // In order to avoid an inconsistent state, make sure it's
    // possible to open both files before rewriting either.
    //
    FILE *pubf = fopen("pubkey", "w");
    if (!pubf) {
        fatal_error(argv[0], "could not create public key file");
    }

    FILE *secretf = fopen("privkey", "w");
    if (!secretf) {
        fclose(pubf);
        fatal_error(argv[0], "could not create private key file");
    }

    rc = fwrite(station_public, sizeof(station_public), 1, pubf);
    if (rc != 1) {
        fclose(pubf);
        fclose(secretf);
        fatal_error(argv[0], "failed to write public key");
    }

    rc = fwrite(station_secret, sizeof(station_secret), 1, secretf);
    if (rc != 1) {
        fclose(pubf);
        fclose(secretf);
        fatal_error(argv[0], "failed to write private key");
    }

    // append the public key to the station key file
    rc = fwrite(station_public, sizeof(station_public), 1, secretf);
    if (rc != 1) {
        fclose(pubf);
        fclose(secretf);
        fatal_error(argv[0], "failed to write public key to station key file");
    }

    fclose(secretf);
    fclose(pubf);

    printf("Wrote files pubkey and privkey\n");
}

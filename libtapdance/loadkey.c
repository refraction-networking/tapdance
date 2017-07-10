
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "loadkey.h"

// Load a station key (and the matching public key) from the given file.
// Returns 0 if successful, < 0 otherwise.
// 
// The key file must contain the private key, followed by the public key.
// 
// The key file could also contain gibberish -- they do not
// contain any sort of integrity check.  So take care with your keys.
 
int td_load_station_key(const char *fname,
                        uint8_t stationkey[TD_KEYLEN_BYTES],
                        uint8_t pubkey[TD_KEYLEN_BYTES])
{
    FILE *fin = fopen(fname, "r");
    int rc;
    char extra;

    if (!fin)
        return -1;

    rc = fread(stationkey, TD_KEYLEN_BYTES, 1, fin);
    if (rc != 1) {
        fclose(fin);
        return -2;
    }

    // If it's a station key, then the public key follows it (as an idenitifer)
    rc = fread(pubkey, TD_KEYLEN_BYTES, 1, fin);
    if (rc != 1) {
        fclose(fin);
        return -3;
    }

    // See if there's anything more in the file, which might indicate that it's
    // a proper key file.
    if (1 != fread(&extra, sizeof(extra), 1, fin)) {
        // TODO: ?
    }

    fclose(fin);

    return 0;
}

// Load a public key from the given file. Returns 0 if successful, < 0 otherwise
int td_load_public_key(const char *fname, uint8_t keybuf[TD_KEYLEN_BYTES])
{
    FILE *fin = fopen(fname, "r");
    int rc;
    char extra;

    if (!fin)
        return -1;

    rc = fread(keybuf, TD_KEYLEN_BYTES, 1, fin);
    if (rc != 1) {
        fclose(fin);
        return -2;
    }

    // See if there's anything more in the file, which might indicate that it's
    // a proper key file.
    if (1 != fread(&extra, sizeof(extra), 1, fin)) {
        // TODO: ?
    }
    fclose(fin);

    return 0;
}

// Print a key to stdout, in hex.
void td_print_key(const uint8_t key[TD_KEYLEN_BYTES])
{
    unsigned int i;
    for (i = 0; i < TD_KEYLEN_BYTES; i++)
        printf("%.2x", key[i]);
}

// Create a newly-malloc'ed string representation of a key
char *td_key2str(const uint8_t key[TD_KEYLEN_BYTES])
{
    char *buf = malloc((2 * TD_KEYLEN_BYTES) + 1);

    unsigned int i;
    for (i = 0; i < TD_KEYLEN_BYTES; i++)
        sprintf(&buf[2 * i], "%.2x", key[i]);

    buf[2 * TD_KEYLEN_BYTES] = 0;
    return buf;
}

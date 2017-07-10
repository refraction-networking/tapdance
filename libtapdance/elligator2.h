//
//  elligator2.h
//  Assuming curve25519; prime p = 2^255-19; curve y^2 = x^3 + A*x^2 + x; A = 486662
//  Elliptic curve points represented as bytes. Each coordinate is 32 bytes.
//  On curve25519, always take canonical y in range 0,..,(p-1)/2. We can ignore y-coord.
//

#ifndef _elligator2_h
#define _elligator2_h



// For the station; given a tag, return the payload.
// Currently, out must support at least 144 bytes
size_t get_payload_from_tag(const unsigned char *station_privkey,
                            unsigned char *stego_payload, size_t stego_len,
                            char *out, size_t out_len);

// Client calls this to get a random shared secret and public point,
// given the station's public key.
void get_encoded_point_and_secret(const unsigned char *station_public,
                                  unsigned char *shared_secret_out,
                                  unsigned char *encoded_point_out);

// For the client; given a payload and a station public key, provides
// an output. Currently, tag_out must be >= 176 byte buffer for
// the given payload lengths we are using
size_t get_tag_from_payload(const unsigned char *payload, size_t payload_len,
                            const unsigned char *station_pubkey,
                            unsigned char *tag_out);

// Takes as input a 32-byte little endian string (technically 255 bits padded to 32 bytes)
// Returns 0 if string could not be decoded, i.e., does not correspond to an elliptic curve point (highly unlikely)
// If possible, outputs 32 byte x-coord of curve25519 point corresponding to input string
int decode(unsigned char *out, const unsigned char *in);


// Takes as input 32 byte little endian encodable curve25519 point;
// high order bit is sign of y value
// Outputs 255-bit (little endian) uniform-looking 32-byte string
// Returns 0 if point could not be encoded as a string, returns 1 otherwise
int encode(unsigned char *out, const unsigned char *in);

#endif

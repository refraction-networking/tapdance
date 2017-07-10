#ifndef SSL_API_H
#define SSL_API_H


#ifdef __cplusplus
extern "C" {
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>

//#include "ssl/ssl_locl.h"
int ssl3_new(SSL *s);
int ssl3_setup_buffers(SSL *s);
int ssl3_connect(SSL *s);
int tls1_change_cipher_state(SSL *s, int which);
int ssl_get_new_session(SSL *s, int session);
const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p);
int tls1_setup_key_block(SSL *s);

// Given a "live" SSL object, setup the master key and cipher suites.
int setup_ssl_secrets(SSL *ssl, const char *master_key, size_t master_key_len,
                      uint16_t cipher_suite, int npn);

int ssl_encrypt(SSL *s, const char *in, int len, char **out);

int ssl_shutdown(SSL *s, char **out);

int ssl_decrypt(SSL *s, const char *in, int len, char **out);


#ifdef __cplusplus
}
#endif


#endif // SSL_API_H

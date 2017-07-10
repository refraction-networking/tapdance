#include "ssl_api.h"
#include <assert.h>
#include <openssl/err.h>

static int fetch_data_from_bio(SSL *s, char **out)
{
    BIO *bio = SSL_get_wbio(s);
    if (!bio) {
        fprintf(stderr, "Couldn't get write BIO for SSL object!\n");
        return -1;
    }
    char *crypted_data;
    long crypted_data_len = BIO_get_mem_data(bio, &crypted_data);
    *out = malloc(crypted_data_len);
    if (!*out) {
        return -1;
    }
    memcpy(*out, crypted_data, crypted_data_len);

    if (BIO_reset(bio) <= 0) {
        fprintf(stderr, "fetch_data_from_bio: BIO_reset returned <= 0\n");
        return -1;
    }
    return crypted_data_len;
}

// Sets *out = malloc(encrypted_data_len), writes the encrypted data into
// *out, and returns encrypted_data_len.
int ssl_encrypt(SSL *s, const char *in, int len, char **out)
{
    if (!BIO_eof(SSL_get_wbio(s))) {
        fprintf(stderr, "ssl_encrypt: Someone left data in the wbio!\n");
        return -1;
    }
    if (SSL_write(s, in, len) < 0) {
        fprintf(stderr, "ssl_encrypt: SSL_write returned < 0\n");
        return -1;
    }
    return fetch_data_from_bio(s, out);
}

int ssl_shutdown(SSL *s, char **out)
{
    int i = SSL_shutdown(s);
    if (i < 0)
        return -1;
    return fetch_data_from_bio(s, out);
}

int ssl_decrypt(SSL *s, const char *in, int len, char **out)
{
    // WARNING: we expect this to be a memory bio...
    BIO *rbio = SSL_get_rbio(s);
    if (!BIO_eof(rbio)) {
        fprintf(stderr, "ssl_decrypt: Someone left data in the rbio!\n");
        return -1;
    }
    if (BIO_write(rbio, in, len) != len) {
        fprintf(stderr, "ssl_decrypt: couldn't write to BIO!\n");
        return -1;
    }

    *out = malloc(len);
    if (!*out) {
		fprintf(stderr, "Bad malloc\n");
        return -1;
    }
    int bytes_decrypted = 0;
    int ret = SSL_read(s, *out + bytes_decrypted, len - bytes_decrypted);
    bytes_decrypted += ret;
    while (ret > 0 && !BIO_eof(rbio) && bytes_decrypted < len) {
        ret = SSL_read(s, *out + bytes_decrypted, len - bytes_decrypted);
        fprintf(stderr, "SSL_read returned: %d\n", ret);
        if (ret > 0)
            bytes_decrypted += ret;
    }
    if (ret < 0)
        ERR_clear_error(); // Consume SSL error

    if (!BIO_eof(rbio))
        fprintf(stderr, "We are leaving data in the rbio! ret: %d\n", ret);

    return bytes_decrypted;
}

//key: 32 bytes ?? 16 bytes for AES-GCM (AES-128)
//iv: 16 bytes ?? 12 bytes for AES-GCM
//mac_secret: 20 bytes ?? 16-bytes for AES-GCM
SSL* get_ssl_obj(const uint8_t *master_key, size_t master_key_len,
                 uint16_t cipher_suite, const uint8_t *server_random,
                 const uint8_t *client_random, int npn)
{
    static SSL_CTX *ctx = 0;
    if (!ctx) {
        SSL_library_init();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLSv1_2_server_method());
        // So that retrying after WANT_WRITE won't break. Not the default
        // because the OpenSSL people are worried that a write() that made no
        // progress might be retried with different data. What other data could
        // we possibly be passing? You aren't returning any "n bytes written",
        // so there is no n to advance by. Shouldn't "different pointer to the
        // same data causes error" be a red flag about your implementation?
        SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "could not init ssl...\n");
        return NULL;
    }

    ssl->type = SSL_ST_ACCEPT;
    ssl->method = TLSv1_2_server_method();

    ssl->rwstate = SSL_NOTHING;
    ssl->in_handshake = 0; /* We're simulating having finished SSL_connect. */
    ssl->handshake_func = ssl3_connect;
    ssl->server = 0;

    ssl->new_session = 0;
    ssl->quiet_shutdown = 0;
    ssl->shutdown = 0;

    ssl->state = SSL_ST_OK;
    ssl->rstate = SSL_ST_READ_HEADER;

    // Handshake stuff, we're not doing a handshake.
    ssl->init_buf = ssl->init_msg = NULL;
    ssl->init_num = ssl->init_off = 0;

    // Let's not touch ssl->param; it's set by SSL_new.
    // Let's leave ssl->cert alone; should be set by SSL_new.
    // Let's leave ssl->sid_ctx_length alone; should be set by SSL_new.

    if (!ssl_get_new_session(ssl, 0)) {
        fprintf(stderr, "Couldn't get session\n");
        return NULL;
    }

    ssl->verify_result = X509_V_OK;  // Just say the cert's valid.

    //ssl->options is set in SSL_new.
    //ssl->mode is set in SSL_new.
    //ssl->max_cert_list is set in SSL_new.

    ssl->client_version = ssl->version;
    //  ssl->max_send_fragment is set in SSL_new.

    ssl->initial_ctx = ssl->ctx;

    // TODO(Tapdance): don't think 1.2 in GCM needs this
    ssl->s3->need_empty_fragments = 1;
    
    ssl->s3->wpend_buf = NULL; //TODO ??

    if (!ssl3_setup_buffers(ssl)) {
        fprintf(stderr, "Couldn't setup ssl3 buffers\n");
        return NULL;
    }

    // TODO: What are these for??
    ssl->s3->tmp.message_size = 12;
    ssl->s3->tmp.message_type = 20;
    ssl->s3->tmp.new_cipher = NULL; //TODO

    ssl->s3->tmp.next_state = 4576; //hehe
    ssl->s3->tmp.new_sym_enc = NULL; //TODO
    ssl->s3->tmp.new_hash = NULL;   //TODO

    if (!ssl_get_new_session(ssl, 0)) {
        fprintf(stderr, "Couldn't initialize session\n");
        return NULL;
    }

    //BIO setup
    SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));

    // TODO(ewust/SPTelex)
    memcpy(ssl->s3->client_random, client_random, 32);
    memcpy(ssl->s3->server_random, server_random, 32);

    if (!setup_ssl_secrets(ssl, master_key, master_key_len, cipher_suite, npn))
    {
        fprintf(stderr, "Couldn't change to telex crypto!\n");
        return NULL;
    }
    return ssl;
}


int setup_ssl_secrets(SSL *ssl, const char *master_key, size_t master_key_len,
                      uint16_t cipher_suite, int npn)
{
    // SSL record sequence numbers should be 1; we just got done with
    // a round of hellos
    ssl->type = SSL_ST_ACCEPT;
    ssl->method = TLSv1_2_server_method();

    memset(ssl->s3->read_sequence, 0, sizeof(ssl->s3->read_sequence));
    memset(ssl->s3->write_sequence, 0, sizeof(ssl->s3->write_sequence));

    // TODO: needed?
    ssl->s3->previous_client_finished_len = 12;
    memcpy(ssl->s3->previous_client_finished, "somefinishedbusiness,ya", 12);

    ssl->s3->previous_server_finished_len = 12;
    memcpy(ssl->s3->previous_server_finished, "jsadfkjwefjaewmfamsawe", 12); 

    ssl->s3->tmp.finish_md_len = 12;
    memcpy(ssl->s3->tmp.finish_md, "akjwemawmefmawe", 12);

    // (was DHE-RSA-AES256-SHA) \x00\x39 ...
    // Set the cipher suite
    ssl->s3->tmp.new_cipher =
        (SSL_CIPHER*)ssl3_get_cipher_by_char(
            (const unsigned char*)&cipher_suite);
    ssl->session->cipher = ssl->s3->tmp.new_cipher;

    ssl->session->master_key_length = master_key_len;
    memcpy(ssl->session->master_key, master_key, master_key_len);
    // Woo! That felt good.

    if (!tls1_setup_key_block(ssl)) {
        fprintf(stderr, "Couldn't set up key block\n");
        return 0;
    }

    // These guys reset ssl->s3->write_sequence and read_sequence
    // respectively....(what else)
    if (!tls1_change_cipher_state(ssl, SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
        fprintf(stderr, "Couldn't change write cipher state\n");
        return 0;
    }
    if (!tls1_change_cipher_state(ssl, SSL3_CHANGE_CIPHER_SERVER_READ)) {
        fprintf(stderr, "Couldn't change read cipher state\n");
        return 0;
    }

    // For TELEX_LEAK_KEY, we have to "consume" the client_finished message,
    // (and "send" the server finished message). This will increase
    // read/write_sequence, as well as change the working iv's for
    // ssl->enc_{write,read}_ctx->iv
    //TODO(ewust): set working iv's here (and possibly remove the following)

    ssl->s3->write_sequence[7] = '\x01';

    if (!npn) {
        // Normal, non-NPN
        ssl->s3->read_sequence[7] = '\x01';
    } else {
        // Consume the NPN NextProtocol Handshake message
        ssl->s3->read_sequence[7] = '\x02';
    }
    return 1;
}

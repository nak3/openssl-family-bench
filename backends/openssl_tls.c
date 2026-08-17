#include "ofb/tls_bench.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifndef OFB_BACKEND_NAME
#define OFB_BACKEND_NAME "openssl-compatible"
#endif

#define OFB_TLS_RECORD_SIZE 16384

struct tls_pair {
    SSL *client;
    SSL *server;
};

struct ofb_tls_backend {
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
    struct tls_pair transfer_pair;
    enum ofb_tls_benchmark benchmark;
    const char *cipher;
    unsigned char *plaintext;
    unsigned char *received;
    size_t message_size;
    volatile unsigned char checksum;
};

static const char *const ciphers[] = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
};

static struct ofb_tls_backend_info info = {
    OFB_BACKEND_NAME,
    NULL,
    ciphers,
    sizeof ciphers / sizeof ciphers[0]
};

const struct ofb_tls_backend_info *
ofb_tls_backend_info(void)
{
    info.version = OpenSSL_version(OPENSSL_VERSION);
    return &info;
}

static void
tls_pair_destroy(struct tls_pair *pair)
{
    SSL_free(pair->client);
    SSL_free(pair->server);
    pair->client = NULL;
    pair->server = NULL;
}

static int
handshake_step(SSL *ssl, int *finished)
{
    int result;
    int error;

    if (*finished) {
        return 0;
    }
    result = SSL_do_handshake(ssl);
    if (result == 1) {
        *finished = 1;
        return 0;
    }
    error = SSL_get_error(ssl, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
        return -1;
    }
    return 0;
}

static int
tls_pair_create(SSL_CTX *client_ctx, SSL_CTX *server_ctx, struct tls_pair *pair)
{
    BIO *client_bio = NULL;
    BIO *server_bio = NULL;
    int client_finished = 0;
    int server_finished = 0;
    unsigned int attempts;

    memset(pair, 0, sizeof *pair);
    pair->client = SSL_new(client_ctx);
    pair->server = SSL_new(server_ctx);
    if (pair->client == NULL || pair->server == NULL ||
        BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1) {
        BIO_free(client_bio);
        BIO_free(server_bio);
        tls_pair_destroy(pair);
        return -1;
    }

    SSL_set_bio(pair->client, client_bio, client_bio);
    SSL_set_bio(pair->server, server_bio, server_bio);
    SSL_set_connect_state(pair->client);
    SSL_set_accept_state(pair->server);

    for (attempts = 0; attempts < 10000; attempts++) {
        if (handshake_step(pair->client, &client_finished) != 0 ||
            handshake_step(pair->server, &server_finished) != 0) {
            tls_pair_destroy(pair);
            return -1;
        }
        if (client_finished && server_finished) {
            return 0;
        }
    }
    tls_pair_destroy(pair);
    return -1;
}

static int
tls_pair_matches(const struct tls_pair *pair, const char *cipher)
{
    return SSL_version(pair->client) == TLS1_3_VERSION &&
           SSL_version(pair->server) == TLS1_3_VERSION &&
           strcmp(SSL_get_cipher_name(pair->client), cipher) == 0 &&
           strcmp(SSL_get_cipher_name(pair->server), cipher) == 0;
}

static int
transfer_once(struct ofb_tls_backend *state)
{
    size_t offset = 0;

    while (offset < state->message_size) {
        size_t chunk = state->message_size - offset;
        size_t received = 0;
        int result;

        if (chunk > OFB_TLS_RECORD_SIZE) {
            chunk = OFB_TLS_RECORD_SIZE;
        }
        result = SSL_write(state->transfer_pair.client, state->plaintext + offset,
                           (int) chunk);
        if (result != (int) chunk) {
            return -1;
        }
        while (received < chunk) {
            result = SSL_read(state->transfer_pair.server,
                              state->received + offset + received,
                              (int) (chunk - received));
            if (result <= 0) {
                return -1;
            }
            received += (size_t) result;
        }
        offset += chunk;
    }
    return 0;
}

int
ofb_tls_backend_create(const struct ofb_tls_params *params,
                       struct ofb_tls_backend **backend)
{
    struct ofb_tls_backend *state;
    size_t i;

    if (params == NULL || backend == NULL || params->message_size > INT_MAX) {
        return -1;
    }
    state = calloc(1, sizeof *state);
    if (state == NULL) {
        return -1;
    }
    state->client_ctx = SSL_CTX_new(TLS_method());
    state->server_ctx = SSL_CTX_new(TLS_method());
    state->benchmark = params->benchmark;
    state->cipher = params->cipher;
    state->message_size = params->message_size;
    state->plaintext = malloc(params->message_size == 0 ? 1 : params->message_size);
    state->received = malloc(params->message_size == 0 ? 1 : params->message_size);

    if (state->client_ctx == NULL || state->server_ctx == NULL ||
        state->plaintext == NULL || state->received == NULL ||
        SSL_CTX_set_min_proto_version(state->client_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(state->client_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_min_proto_version(state->server_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(state->server_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(state->client_ctx, params->cipher) != 1 ||
        SSL_CTX_set_ciphersuites(state->server_ctx, params->cipher) != 1 ||
        SSL_CTX_use_certificate_file(state->server_ctx, params->certificate_path,
                                     SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(state->server_ctx, params->private_key_path,
                                    SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(state->server_ctx) != 1) {
        ofb_tls_backend_destroy(state);
        return -1;
    }
    SSL_CTX_set_verify(state->client_ctx, SSL_VERIFY_NONE, NULL);
    for (i = 0; i < params->message_size; i++) {
        state->plaintext[i] = (unsigned char) (i * 29U + 11U);
    }
    if (params->benchmark == OFB_TLS_TRANSFER &&
        tls_pair_create(state->client_ctx, state->server_ctx,
                        &state->transfer_pair) != 0) {
        ofb_tls_backend_destroy(state);
        return -1;
    }
    *backend = state;
    return 0;
}

int
ofb_tls_backend_verify(struct ofb_tls_backend *state)
{
    struct tls_pair pair;

    if (state->benchmark == OFB_TLS_HANDSHAKE) {
        if (tls_pair_create(state->client_ctx, state->server_ctx, &pair) != 0) {
            return -1;
        }
        if (!tls_pair_matches(&pair, state->cipher)) {
            tls_pair_destroy(&pair);
            return -1;
        }
        tls_pair_destroy(&pair);
        return 0;
    }
    if (!tls_pair_matches(&state->transfer_pair, state->cipher) ||
        transfer_once(state) != 0 ||
        CRYPTO_memcmp(state->plaintext, state->received, state->message_size) != 0) {
        return -1;
    }
    return 0;
}

int
ofb_tls_backend_run_batch(struct ofb_tls_backend *state, uint64_t iterations)
{
    uint64_t i;

    if (state->benchmark == OFB_TLS_HANDSHAKE) {
        for (i = 0; i < iterations; i++) {
            struct tls_pair pair;
            if (tls_pair_create(state->client_ctx, state->server_ctx, &pair) != 0) {
                return -1;
            }
            tls_pair_destroy(&pair);
        }
    } else {
        for (i = 0; i < iterations; i++) {
            if (transfer_once(state) != 0) {
                return -1;
            }
        }
        if (CRYPTO_memcmp(state->plaintext, state->received,
                          state->message_size) != 0) {
            return -1;
        }
        state->checksum ^= state->received[state->message_size == 0 ?
                                            0 : state->message_size - 1];
    }
    return 0;
}

void
ofb_tls_backend_destroy(struct ofb_tls_backend *state)
{
    if (state == NULL) {
        return;
    }
    tls_pair_destroy(&state->transfer_pair);
    SSL_CTX_free(state->client_ctx);
    SSL_CTX_free(state->server_ctx);
    free(state->plaintext);
    free(state->received);
    free(state);
}

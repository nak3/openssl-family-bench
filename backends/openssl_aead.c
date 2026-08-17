#include "ofb/bench.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define OFB_TAG_SIZE 16
#define OFB_NONCE_SIZE 12

#ifndef OFB_BACKEND_NAME
#define OFB_BACKEND_NAME "openssl-compatible"
#endif

struct ofb_backend {
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    enum ofb_operation operation;
    unsigned char key[32];
    unsigned char nonce[OFB_NONCE_SIZE];
    unsigned char tag[OFB_TAG_SIZE];
    unsigned char *aad;
    unsigned char *plaintext;
    unsigned char *ciphertext;
    unsigned char *output;
    size_t aad_size;
    size_t message_size;
    volatile unsigned char checksum;
};

static const char *const algorithms[] = {
    "AES-128-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305"
};

static struct ofb_backend_info info = {
    OFB_BACKEND_NAME,
    NULL,
    algorithms,
    sizeof algorithms / sizeof algorithms[0]
};

static const EVP_CIPHER *
find_cipher(const char *name)
{
    if (strcmp(name, "AES-128-GCM") == 0) {
        return EVP_aes_128_gcm();
    }
    if (strcmp(name, "AES-256-GCM") == 0) {
        return EVP_aes_256_gcm();
    }
    if (strcmp(name, "CHACHA20-POLY1305") == 0) {
        return EVP_chacha20_poly1305();
    }
    return NULL;
}

const struct ofb_backend_info *
ofb_backend_info(void)
{
    info.version = OpenSSL_version(OPENSSL_VERSION);
    return &info;
}

static int
encrypt_once(struct ofb_backend *state, unsigned char *ciphertext,
             unsigned char tag[OFB_TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int final_len;
    int ok = -1;

    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, state->cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, OFB_NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, state->key, state->nonce) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &len, state->aad, (int) state->aad_size) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, state->plaintext,
                          (int) state->message_size) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, OFB_TAG_SIZE, tag) != 1) {
        goto out;
    }
    ok = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int
decrypt_once(struct ofb_backend *state, const unsigned char *ciphertext,
             const unsigned char tag[OFB_TAG_SIZE], unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int final_len;
    int ok = -1;

    if (ctx == NULL ||
        EVP_DecryptInit_ex(ctx, state->cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, OFB_NONCE_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, state->key, state->nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &len, state->aad, (int) state->aad_size) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                          (int) state->message_size) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, OFB_TAG_SIZE, (void *) tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) {
        goto out;
    }
    ok = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int
ofb_backend_create(const struct ofb_params *params, struct ofb_backend **backend)
{
    struct ofb_backend *state;
    size_t i;

    if (params == NULL || backend == NULL || params->message_size > INT_MAX ||
        params->aad_size > INT_MAX) {
        return -1;
    }

    state = calloc(1, sizeof *state);
    if (state == NULL) {
        return -1;
    }
    state->cipher = find_cipher(params->algorithm);
    state->ctx = EVP_CIPHER_CTX_new();
    state->operation = params->operation;
    state->message_size = params->message_size;
    state->aad_size = params->aad_size;
    state->aad = calloc(params->aad_size == 0 ? 1 : params->aad_size, 1);
    state->plaintext = malloc(params->message_size == 0 ? 1 : params->message_size);
    state->ciphertext = malloc(params->message_size + OFB_TAG_SIZE);
    state->output = malloc(params->message_size + OFB_TAG_SIZE);

    if (state->cipher == NULL || state->ctx == NULL || state->aad == NULL ||
        state->plaintext == NULL || state->ciphertext == NULL || state->output == NULL) {
        ofb_backend_destroy(state);
        return -1;
    }
    for (i = 0; i < params->message_size; i++) {
        state->plaintext[i] = (unsigned char) (i * 31U + 7U);
    }
    for (i = 0; i < sizeof state->key; i++) {
        state->key[i] = (unsigned char) (i + 1U);
    }
    for (i = 0; i < sizeof state->nonce; i++) {
        state->nonce[i] = (unsigned char) (0xa0U + i);
    }
    if (encrypt_once(state, state->ciphertext, state->tag) != 0) {
        ofb_backend_destroy(state);
        return -1;
    }
    *backend = state;
    return 0;
}

int
ofb_backend_verify(struct ofb_backend *state)
{
    unsigned char tag[OFB_TAG_SIZE];

    if (encrypt_once(state, state->output, tag) != 0 ||
        CRYPTO_memcmp(state->output, state->ciphertext, state->message_size) != 0 ||
        CRYPTO_memcmp(tag, state->tag, sizeof tag) != 0 ||
        decrypt_once(state, state->ciphertext, state->tag, state->output) != 0 ||
        CRYPTO_memcmp(state->output, state->plaintext, state->message_size) != 0) {
        return -1;
    }
    return 0;
}

int
ofb_backend_run_batch(struct ofb_backend *state, uint64_t iterations)
{
    uint64_t i;
    int len;
    int final_len;

    for (i = 0; i < iterations; i++) {
        if (state->operation == OFB_SEAL) {
            if (EVP_EncryptInit_ex(state->ctx, state->cipher, NULL, NULL, NULL) != 1 ||
                EVP_CIPHER_CTX_ctrl(state->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    OFB_NONCE_SIZE, NULL) != 1 ||
                EVP_EncryptInit_ex(state->ctx, NULL, NULL, state->key, state->nonce) != 1 ||
                EVP_EncryptUpdate(state->ctx, NULL, &len, state->aad,
                                  (int) state->aad_size) != 1 ||
                EVP_EncryptUpdate(state->ctx, state->output, &len, state->plaintext,
                                  (int) state->message_size) != 1 ||
                EVP_EncryptFinal_ex(state->ctx, state->output + len, &final_len) != 1 ||
                EVP_CIPHER_CTX_ctrl(state->ctx, EVP_CTRL_AEAD_GET_TAG,
                                    OFB_TAG_SIZE, state->tag) != 1) {
                return -1;
            }
        } else {
            if (EVP_DecryptInit_ex(state->ctx, state->cipher, NULL, NULL, NULL) != 1 ||
                EVP_CIPHER_CTX_ctrl(state->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    OFB_NONCE_SIZE, NULL) != 1 ||
                EVP_DecryptInit_ex(state->ctx, NULL, NULL, state->key, state->nonce) != 1 ||
                EVP_DecryptUpdate(state->ctx, NULL, &len, state->aad,
                                  (int) state->aad_size) != 1 ||
                EVP_DecryptUpdate(state->ctx, state->output, &len, state->ciphertext,
                                  (int) state->message_size) != 1 ||
                EVP_CIPHER_CTX_ctrl(state->ctx, EVP_CTRL_AEAD_SET_TAG,
                                    OFB_TAG_SIZE, state->tag) != 1 ||
                EVP_DecryptFinal_ex(state->ctx, state->output + len, &final_len) != 1) {
                return -1;
            }
        }
    }
    state->checksum ^= state->output[state->message_size == 0 ? 0 : state->message_size - 1];
    return 0;
}

void
ofb_backend_destroy(struct ofb_backend *state)
{
    if (state == NULL) {
        return;
    }
    EVP_CIPHER_CTX_free(state->ctx);
    free(state->aad);
    free(state->plaintext);
    free(state->ciphertext);
    free(state->output);
    free(state);
}

#include "ofb/bench.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum primitive_kind {
    PRIMITIVE_CIPHER,
    PRIMITIVE_DIGEST,
    PRIMITIVE_HMAC
};

struct primitive {
    const char *name;
    enum primitive_kind kind;
    const EVP_CIPHER *(*cipher)(void);
    const EVP_MD *(*digest)(void);
};

static const struct primitive primitives[] = {
    { "AES-128-CBC", PRIMITIVE_CIPHER, EVP_aes_128_cbc, NULL },
    { "AES-256-CBC", PRIMITIVE_CIPHER, EVP_aes_256_cbc, NULL },
    { "SHA-256", PRIMITIVE_DIGEST, NULL, EVP_sha256 },
    { "SHA-512", PRIMITIVE_DIGEST, NULL, EVP_sha512 },
    { "HMAC-SHA256", PRIMITIVE_HMAC, NULL, EVP_sha256 },
};

static void
usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s --primitive NAME --operation NAME [options]\n"
            "  --primitive NAME    AES-128-CBC, AES-256-CBC, SHA-256,"
            " SHA-512, HMAC-SHA256\n"
            "  --operation NAME    encrypt, decrypt, digest, or mac\n"
            "  --size BYTES        payload size (default: 16384)\n"
            "  --sample-ms MS      workload duration (default: 2000)\n"
            "  --list              list primitive/operation pairs\n"
            "  --help              show this help\n",
            program);
}

static int
parse_u64(const char *text, uint64_t *value)
{
    char *end;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || *text == '\0' || *end != '\0') {
        return -1;
    }
    *value = (uint64_t) parsed;
    return 0;
}

static const struct primitive *
find_primitive(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof primitives / sizeof primitives[0]; i++) {
        if (strcmp(primitives[i].name, name) == 0) {
            return &primitives[i];
        }
    }
    return NULL;
}

static int
operation_matches(const struct primitive *primitive, const char *operation)
{
    if (primitive->kind == PRIMITIVE_CIPHER) {
        return strcmp(operation, "encrypt") == 0 ||
               strcmp(operation, "decrypt") == 0;
    }
    if (primitive->kind == PRIMITIVE_DIGEST) {
        return strcmp(operation, "digest") == 0;
    }
    return strcmp(operation, "mac") == 0;
}

static int
prepare_ciphertext(const EVP_CIPHER *cipher, const unsigned char *key,
                   const unsigned char *iv, const unsigned char *input,
                   unsigned char *output, size_t size)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int final_len;
    int ok = -1;

    if (ctx != NULL &&
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_EncryptUpdate(ctx, output, &len, input, (int) size) == 1 &&
        EVP_EncryptFinal_ex(ctx, output + len, &final_len) == 1) {
        ok = 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int
run_cipher(const struct primitive *primitive, const char *operation,
           const unsigned char *key, const unsigned char *iv,
           const unsigned char *input, const unsigned char *ciphertext,
           unsigned char *output, size_t size, uint64_t target_ns,
           uint64_t *iterations, volatile unsigned char *checksum)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = primitive->cipher();
    const unsigned char *source = strcmp(operation, "encrypt") == 0 ?
                                  input : ciphertext;
    int encrypt = strcmp(operation, "encrypt") == 0;
    uint64_t start = ofb_now_ns();
    uint64_t count = 0;

    if (ctx == NULL || start == 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    do {
        unsigned batch;
        for (batch = 0; batch < 256; batch++) {
            int len;
            int final_len;
            if (EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, encrypt) != 1 ||
                EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
                EVP_CipherUpdate(ctx, output, &len, source, (int) size) != 1 ||
                EVP_CipherFinal_ex(ctx, output + len, &final_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return -1;
            }
            count++;
        }
    } while (ofb_now_ns() - start < target_ns);
    *checksum ^= output[size - 1];
    *iterations = count;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int
run_digest(const struct primitive *primitive, const unsigned char *input,
           size_t size, uint64_t target_ns, uint64_t *iterations,
           volatile unsigned char *checksum)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char output[EVP_MAX_MD_SIZE];
    uint64_t start = ofb_now_ns();
    uint64_t count = 0;

    if (ctx == NULL || start == 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    do {
        unsigned batch;
        for (batch = 0; batch < 256; batch++) {
            unsigned output_size;
            if (EVP_DigestInit_ex(ctx, primitive->digest(), NULL) != 1 ||
                EVP_DigestUpdate(ctx, input, size) != 1 ||
                EVP_DigestFinal_ex(ctx, output, &output_size) != 1) {
                EVP_MD_CTX_free(ctx);
                return -1;
            }
            count++;
        }
    } while (ofb_now_ns() - start < target_ns);
    *checksum ^= output[0];
    *iterations = count;
    EVP_MD_CTX_free(ctx);
    return 0;
}

static int
run_hmac(const struct primitive *primitive, const unsigned char *key,
         const unsigned char *input, size_t size, uint64_t target_ns,
         uint64_t *iterations, volatile unsigned char *checksum)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned char output[EVP_MAX_MD_SIZE];
    uint64_t start = ofb_now_ns();
    uint64_t count = 0;

    if (ctx == NULL || start == 0) {
        HMAC_CTX_free(ctx);
        return -1;
    }
    do {
        unsigned batch;
        for (batch = 0; batch < 256; batch++) {
            unsigned output_size;
            if (HMAC_Init_ex(ctx, key, 32, primitive->digest(), NULL) != 1 ||
                HMAC_Update(ctx, input, size) != 1 ||
                HMAC_Final(ctx, output, &output_size) != 1) {
                HMAC_CTX_free(ctx);
                return -1;
            }
            count++;
        }
    } while (ofb_now_ns() - start < target_ns);
    *checksum ^= output[0];
    *iterations = count;
    HMAC_CTX_free(ctx);
    return 0;
}

int
main(int argc, char **argv)
{
    const char *primitive_name = NULL;
    const char *operation = NULL;
    const struct primitive *primitive;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char *input;
    unsigned char *ciphertext;
    unsigned char *output;
    size_t size = 16384;
    uint64_t sample_ms = 2000;
    uint64_t iterations = 0;
    volatile unsigned char checksum = 0;
    int i;
    int result;

    for (i = 1; i < argc; i++) {
        uint64_t parsed;
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--list") == 0) {
            puts("AES-128-CBC encrypt\nAES-128-CBC decrypt");
            puts("AES-256-CBC encrypt\nAES-256-CBC decrypt");
            puts("SHA-256 digest\nSHA-512 digest\nHMAC-SHA256 mac");
            return 0;
        }
        if (i + 1 >= argc) {
            usage(stderr, argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--primitive") == 0) {
            primitive_name = argv[++i];
        } else if (strcmp(argv[i], "--operation") == 0) {
            operation = argv[++i];
        } else if (strcmp(argv[i], "--size") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed == 0 ||
                parsed > INT_MAX) {
                fprintf(stderr, "invalid --size\n");
                return 2;
            }
            size = (size_t) parsed;
        } else if (strcmp(argv[i], "--sample-ms") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed == 0 ||
                parsed > UINT64_MAX / 1000000ULL) {
                fprintf(stderr, "invalid --sample-ms\n");
                return 2;
            }
            sample_ms = parsed;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 2;
        }
    }
    primitive = primitive_name == NULL ? NULL : find_primitive(primitive_name);
    if (primitive == NULL || operation == NULL ||
        !operation_matches(primitive, operation)) {
        usage(stderr, argv[0]);
        return 2;
    }
    if (primitive->kind == PRIMITIVE_CIPHER && size % 16 != 0) {
        fprintf(stderr, "AES-CBC --size must be a multiple of 16\n");
        return 2;
    }

    input = malloc(size);
    ciphertext = malloc(size + EVP_MAX_BLOCK_LENGTH);
    output = malloc(size + EVP_MAX_BLOCK_LENGTH);
    if (input == NULL || ciphertext == NULL || output == NULL) {
        free(input);
        free(ciphertext);
        free(output);
        return 1;
    }
    for (i = 0; i < (int) size; i++) {
        input[i] = (unsigned char) (i * 31U + 7U);
    }
    if (primitive->kind == PRIMITIVE_CIPHER &&
        prepare_ciphertext(primitive->cipher(), key, iv, input,
                           ciphertext, size) != 0) {
        result = -1;
    } else if (primitive->kind == PRIMITIVE_CIPHER) {
        result = run_cipher(primitive, operation, key, iv, input, ciphertext,
                            output, size, sample_ms * 1000000ULL,
                            &iterations, &checksum);
    } else if (primitive->kind == PRIMITIVE_DIGEST) {
        result = run_digest(primitive, input, size, sample_ms * 1000000ULL,
                            &iterations, &checksum);
    } else {
        result = run_hmac(primitive, key, input, size,
                          sample_ms * 1000000ULL, &iterations, &checksum);
    }
    free(input);
    free(ciphertext);
    free(output);
    if (result != 0) {
        fprintf(stderr, "primitive workload failed\n");
        return 1;
    }
    printf("{\"architecture\":\"%s\",\"backend\":\"%s\","
           "\"version\":\"%s\",\"primitive\":\"%s\","
           "\"operation\":\"%s\",\"message_bytes\":%zu,"
           "\"iterations\":%" PRIu64 ",\"checksum\":%u}\n",
           OFB_ARCHITECTURE, OFB_BACKEND_NAME,
           OpenSSL_version(OPENSSL_VERSION), primitive->name, operation,
           size, iterations, (unsigned) checksum);
    return 0;
}

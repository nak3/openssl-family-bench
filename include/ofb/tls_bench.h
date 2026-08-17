#ifndef OFB_TLS_BENCH_H
#define OFB_TLS_BENCH_H

#include <stddef.h>
#include <stdint.h>

enum ofb_tls_benchmark {
    OFB_TLS_HANDSHAKE,
    OFB_TLS_TRANSFER
};

struct ofb_tls_params {
    const char *cipher;
    const char *certificate_path;
    const char *private_key_path;
    enum ofb_tls_benchmark benchmark;
    size_t message_size;
};

struct ofb_tls_backend;

struct ofb_tls_backend_info {
    const char *name;
    const char *version;
    const char *const *ciphers;
    size_t cipher_count;
};

const struct ofb_tls_backend_info *ofb_tls_backend_info(void);
int ofb_tls_backend_create(const struct ofb_tls_params *params,
                           struct ofb_tls_backend **backend);
int ofb_tls_backend_verify(struct ofb_tls_backend *backend);
int ofb_tls_backend_run_batch(struct ofb_tls_backend *backend,
                              uint64_t iterations);
void ofb_tls_backend_destroy(struct ofb_tls_backend *backend);

#endif

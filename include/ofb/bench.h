#ifndef OFB_BENCH_H
#define OFB_BENCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum ofb_operation {
    OFB_SEAL,
    OFB_OPEN
};

struct ofb_params {
    const char *algorithm;
    enum ofb_operation operation;
    size_t message_size;
    size_t aad_size;
};

struct ofb_backend;

struct ofb_backend_info {
    const char *name;
    const char *version;
    const char *const *algorithms;
    size_t algorithm_count;
};

const struct ofb_backend_info *ofb_backend_info(void);
int ofb_backend_create(const struct ofb_params *params, struct ofb_backend **backend);
int ofb_backend_verify(struct ofb_backend *backend);
int ofb_backend_run_batch(struct ofb_backend *backend, uint64_t iterations);
void ofb_backend_destroy(struct ofb_backend *backend);

uint64_t ofb_now_ns(void);

struct ofb_sample {
    uint64_t iterations;
    uint64_t elapsed_ns;
    uint64_t bytes;
};

int ofb_run_sample(struct ofb_backend *backend, uint64_t iterations,
                   size_t message_size, struct ofb_sample *sample);
int ofb_calibrate(struct ofb_backend *backend, size_t message_size,
                  uint64_t target_ns, uint64_t *iterations);

#endif

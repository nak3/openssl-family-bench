#include "ofb/bench.h"

#include <limits.h>

int
ofb_run_sample(struct ofb_backend *backend, uint64_t iterations,
               size_t message_size, struct ofb_sample *sample)
{
    uint64_t start;
    uint64_t end;

    start = ofb_now_ns();
    if (start == 0 || ofb_backend_run_batch(backend, iterations) != 0) {
        return -1;
    }
    end = ofb_now_ns();
    if (end <= start ||
        (message_size != 0 && iterations > UINT64_MAX / message_size)) {
        return -1;
    }

    sample->iterations = iterations;
    sample->elapsed_ns = end - start;
    sample->bytes = iterations * (uint64_t) message_size;
    return 0;
}

int
ofb_calibrate(struct ofb_backend *backend, size_t message_size,
              uint64_t target_ns, uint64_t *iterations)
{
    struct ofb_sample sample;
    uint64_t count = 64;

    for (;;) {
        if (ofb_run_sample(backend, count, message_size, &sample) != 0) {
            return -1;
        }
        if (sample.elapsed_ns >= target_ns / 8 || count > UINT64_MAX / 2) {
            break;
        }
        count *= 2;
    }

    if (sample.elapsed_ns < target_ns && sample.elapsed_ns != 0) {
        long double scaled = (long double) count * (long double) target_ns /
                             (long double) sample.elapsed_ns;
        if (scaled < (long double) UINT64_MAX) {
            count = (uint64_t) scaled;
        }
    }
    if (count == 0) {
        count = 1;
    }
    *iterations = count;
    return 0;
}

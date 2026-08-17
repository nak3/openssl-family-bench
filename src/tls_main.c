#include "ofb/bench.h"
#include "ofb/tls_bench.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef OFB_DEFAULT_CERT_PATH
#define OFB_DEFAULT_CERT_PATH "testdata/server-cert.pem"
#endif

#ifndef OFB_DEFAULT_KEY_PATH
#define OFB_DEFAULT_KEY_PATH "testdata/server-key.pem"
#endif

struct options {
    const char *benchmark;
    const char *cipher;
    const char *format;
    const char *certificate_path;
    const char *private_key_path;
    size_t size;
    unsigned samples;
    uint64_t sample_ns;
    int size_set;
};

struct timed_sample {
    uint64_t iterations;
    uint64_t elapsed_ns;
    uint64_t bytes;
};

static void
usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s [options]\n"
            "  --benchmark NAME    handshake, transfer, or all (default: all)\n"
            "  --cipher NAME       TLS 1.3 cipher suite or all (default: all)\n"
            "  --size BYTES        transfer size (default: 1024, 16384)\n"
            "  --samples COUNT     samples per case (default: 7)\n"
            "  --sample-ms MS      target duration per sample (default: 250)\n"
            "  --format FORMAT     jsonl or text (default: jsonl)\n"
            "  --cert PATH         server certificate PEM\n"
            "  --key PATH          server private key PEM\n"
            "  --list              list cipher suites\n"
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

static int
run_timed(struct ofb_tls_backend *backend, uint64_t iterations,
          enum ofb_tls_benchmark benchmark, size_t message_size,
          struct timed_sample *sample)
{
    uint64_t start = ofb_now_ns();
    uint64_t end;

    if (start == 0 || ofb_tls_backend_run_batch(backend, iterations) != 0) {
        return -1;
    }
    end = ofb_now_ns();
    if (end <= start ||
        (benchmark == OFB_TLS_TRANSFER && message_size != 0 &&
         iterations > UINT64_MAX / message_size)) {
        return -1;
    }
    sample->iterations = iterations;
    sample->elapsed_ns = end - start;
    sample->bytes = benchmark == OFB_TLS_TRANSFER ?
                    iterations * (uint64_t) message_size : 0;
    return 0;
}

static int
calibrate(struct ofb_tls_backend *backend, enum ofb_tls_benchmark benchmark,
          size_t message_size, uint64_t target_ns, uint64_t *iterations)
{
    struct timed_sample sample;
    uint64_t count = benchmark == OFB_TLS_HANDSHAKE ? 1 : 16;

    for (;;) {
        if (run_timed(backend, count, benchmark, message_size, &sample) != 0) {
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
    *iterations = count == 0 ? 1 : count;
    return 0;
}

static int
run_case(const struct options *options, const char *cipher,
         enum ofb_tls_benchmark benchmark, size_t message_size)
{
    const struct ofb_tls_backend_info *info = ofb_tls_backend_info();
    const char *benchmark_name = benchmark == OFB_TLS_HANDSHAKE ?
                                 "handshake" : "transfer";
    struct ofb_tls_params params = {
        cipher, options->certificate_path, options->private_key_path,
        benchmark, message_size
    };
    struct ofb_tls_backend *backend = NULL;
    struct timed_sample sample;
    uint64_t iterations;
    unsigned i;

    if (ofb_tls_backend_create(&params, &backend) != 0) {
        fprintf(stderr, "TLS backend creation failed: %s/%s/%zu\n",
                cipher, benchmark_name, message_size);
        return -1;
    }
    if (ofb_tls_backend_verify(backend) != 0 ||
        calibrate(backend, benchmark, message_size, options->sample_ns,
                  &iterations) != 0) {
        fprintf(stderr, "TLS verification or calibration failed: %s/%s/%zu\n",
                cipher, benchmark_name, message_size);
        ofb_tls_backend_destroy(backend);
        return -1;
    }

    for (i = 0; i < options->samples; i++) {
        long double rate;
        if (run_timed(backend, iterations, benchmark, message_size, &sample) != 0) {
            fprintf(stderr, "TLS benchmark failed: %s/%s/%zu\n",
                    cipher, benchmark_name, message_size);
            ofb_tls_backend_destroy(backend);
            return -1;
        }
        if (benchmark == OFB_TLS_HANDSHAKE) {
            rate = (long double) sample.iterations * 1000000000.0L /
                   (long double) sample.elapsed_ns;
        } else {
            rate = (long double) sample.bytes * 1000000000.0L /
                   (long double) sample.elapsed_ns / 1048576.0L;
        }

        if (strcmp(options->format, "jsonl") == 0) {
            printf("{\"schema_version\":1,\"architecture\":\"%s\","
                   "\"backend\":\"%s\",\"version\":\"%s\","
                   "\"benchmark\":\"tls-%s\",\"tls_version\":\"TLSv1.3\","
                   "\"cipher\":\"%s\",\"message_bytes\":%zu,\"sample\":%u,"
                   "\"iterations\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64,
                   OFB_ARCHITECTURE, info->name, info->version,
                   benchmark_name, cipher,
                   message_size, i, sample.iterations, sample.elapsed_ns);
            if (benchmark == OFB_TLS_HANDSHAKE) {
                printf(",\"handshakes_per_second\":%.3Lf}\n", rate);
            } else {
                printf(",\"bytes\":%" PRIu64 ",\"mib_per_second\":%.3Lf}\n",
                       sample.bytes, rate);
            }
        } else if (benchmark == OFB_TLS_HANDSHAKE) {
            printf("%-29s handshake sample=%u  %10.2Lf handshakes/s\n",
                   cipher, i, rate);
        } else {
            printf("%-29s transfer %7zu bytes  sample=%u  %10.2Lf MiB/s\n",
                   cipher, message_size, i, rate);
        }
    }
    ofb_tls_backend_destroy(backend);
    return 0;
}

int
main(int argc, char **argv)
{
    static const size_t default_sizes[] = { 1024, 16384 };
    struct options options = {
        "all", "all", "jsonl", OFB_DEFAULT_CERT_PATH, OFB_DEFAULT_KEY_PATH,
        0, 7, 250000000ULL, 0
    };
    const struct ofb_tls_backend_info *info;
    uint64_t parsed;
    size_t cipher_index;
    size_t size_index;
    int matched = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--list") == 0) {
            info = ofb_tls_backend_info();
            for (cipher_index = 0; cipher_index < info->cipher_count; cipher_index++) {
                puts(info->ciphers[cipher_index]);
            }
            return 0;
        }
        if (i + 1 >= argc) {
            usage(stderr, argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--benchmark") == 0) {
            options.benchmark = argv[++i];
        } else if (strcmp(argv[i], "--cipher") == 0) {
            options.cipher = argv[++i];
        } else if (strcmp(argv[i], "--format") == 0) {
            options.format = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0) {
            options.certificate_path = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0) {
            options.private_key_path = argv[++i];
        } else if (strcmp(argv[i], "--size") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed == 0 || parsed > INT_MAX) {
                fprintf(stderr, "invalid --size\n");
                return 2;
            }
            options.size = (size_t) parsed;
            options.size_set = 1;
        } else if (strcmp(argv[i], "--samples") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed == 0 || parsed > UINT_MAX) {
                fprintf(stderr, "invalid --samples\n");
                return 2;
            }
            options.samples = (unsigned) parsed;
        } else if (strcmp(argv[i], "--sample-ms") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed == 0 ||
                parsed > UINT64_MAX / 1000000ULL) {
                fprintf(stderr, "invalid --sample-ms\n");
                return 2;
            }
            options.sample_ns = parsed * 1000000ULL;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 2;
        }
    }

    if ((strcmp(options.benchmark, "all") != 0 &&
         strcmp(options.benchmark, "handshake") != 0 &&
         strcmp(options.benchmark, "transfer") != 0) ||
        (strcmp(options.format, "jsonl") != 0 &&
         strcmp(options.format, "text") != 0)) {
        fprintf(stderr, "invalid benchmark or format\n");
        return 2;
    }

    info = ofb_tls_backend_info();
    for (cipher_index = 0; cipher_index < info->cipher_count; cipher_index++) {
        const char *cipher = info->ciphers[cipher_index];
        if (strcmp(options.cipher, "all") != 0 &&
            strcmp(options.cipher, cipher) != 0) {
            continue;
        }
        matched = 1;
        if (strcmp(options.benchmark, "all") == 0 ||
            strcmp(options.benchmark, "handshake") == 0) {
            if (run_case(&options, cipher, OFB_TLS_HANDSHAKE, 0) != 0) return 1;
        }
        if (strcmp(options.benchmark, "all") == 0 ||
            strcmp(options.benchmark, "transfer") == 0) {
            for (size_index = 0; size_index < (options.size_set ? 1 : 2); size_index++) {
                size_t size = options.size_set ? options.size : default_sizes[size_index];
                if (run_case(&options, cipher, OFB_TLS_TRANSFER, size) != 0) return 1;
            }
        }
    }
    if (!matched) {
        fprintf(stderr, "unsupported cipher: %s\n", options.cipher);
        return 2;
    }
    return 0;
}

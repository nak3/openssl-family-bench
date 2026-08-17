#include "ofb/bench.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct options {
    const char *algorithm;
    const char *operation;
    const char *format;
    size_t size;
    size_t aad_size;
    unsigned samples;
    uint64_t sample_ns;
    int size_set;
};

static void
usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s [options]\n"
            "  --algorithm NAME    algorithm or 'all' (default: all)\n"
            "  --operation NAME    seal, open, or all (default: all)\n"
            "  --size BYTES        message size (default: 64, 1024, 16384)\n"
            "  --aad-size BYTES    additional data size (default: 13)\n"
            "  --samples COUNT     samples per case (default: 7)\n"
            "  --sample-ms MS      target duration per sample (default: 250)\n"
            "  --format FORMAT     jsonl or text (default: jsonl)\n"
            "  --list              list algorithms\n"
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
algorithm_selected(const struct options *options, const char *algorithm)
{
    return strcmp(options->algorithm, "all") == 0 ||
           strcmp(options->algorithm, algorithm) == 0;
}

static int
run_case(const struct options *options, const char *algorithm,
         enum ofb_operation operation, size_t message_size)
{
    const struct ofb_backend_info *backend_info = ofb_backend_info();
    const char *operation_name = operation == OFB_SEAL ? "seal" : "open";
    struct ofb_params params = { algorithm, operation, message_size, options->aad_size };
    struct ofb_backend *backend = NULL;
    struct ofb_sample sample;
    uint64_t iterations;
    unsigned i;

    if (ofb_backend_create(&params, &backend) != 0) {
        fprintf(stderr, "backend creation failed: %s/%s/%zu\n",
                algorithm, operation_name, message_size);
        ofb_backend_destroy(backend);
        return -1;
    }
    if (ofb_backend_verify(backend) != 0) {
        fprintf(stderr, "correctness verification failed: %s/%s/%zu\n",
                algorithm, operation_name, message_size);
        ofb_backend_destroy(backend);
        return -1;
    }
    if (ofb_calibrate(backend, message_size, options->sample_ns, &iterations) != 0) {
        fprintf(stderr, "calibration failed: %s/%s/%zu\n",
                algorithm, operation_name, message_size);
        ofb_backend_destroy(backend);
        return -1;
    }

    for (i = 0; i < options->samples; i++) {
        long double mib_per_second;
        if (ofb_run_sample(backend, iterations, message_size, &sample) != 0) {
            fprintf(stderr, "benchmark run failed: %s/%s/%zu\n",
                    algorithm, operation_name, message_size);
            ofb_backend_destroy(backend);
            return -1;
        }
        mib_per_second = (long double) sample.bytes * 1000000000.0L /
                         (long double) sample.elapsed_ns / 1048576.0L;
        if (strcmp(options->format, "jsonl") == 0) {
            printf("{\"schema_version\":1,\"backend\":\"%s\",\"version\":\"%s\","
                   "\"algorithm\":\"%s\",\"operation\":\"%s\","
                   "\"message_bytes\":%zu,\"aad_bytes\":%zu,\"sample\":%u,"
                   "\"iterations\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ","
                   "\"bytes\":%" PRIu64 ",\"mib_per_second\":%.3Lf}\n",
                   backend_info->name, backend_info->version, algorithm, operation_name,
                   message_size, options->aad_size, i, sample.iterations,
                   sample.elapsed_ns, sample.bytes, mib_per_second);
        } else {
            printf("%-20s %-4s %7zu bytes  sample=%u  %10.2Lf MiB/s\n",
                   algorithm, operation_name, message_size, i, mib_per_second);
        }
    }
    ofb_backend_destroy(backend);
    return 0;
}

int
main(int argc, char **argv)
{
    static const size_t default_sizes[] = { 64, 1024, 16384 };
    struct options options = { "all", "all", "jsonl", 0, 13, 7, 250000000ULL, 0 };
    const struct ofb_backend_info *info;
    uint64_t parsed;
    size_t algorithm_index;
    size_t size_index;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--list") == 0) {
            info = ofb_backend_info();
            for (algorithm_index = 0; algorithm_index < info->algorithm_count;
                 algorithm_index++) {
                puts(info->algorithms[algorithm_index]);
            }
            return 0;
        }
        if (i + 1 >= argc) {
            usage(stderr, argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--algorithm") == 0) {
            options.algorithm = argv[++i];
        } else if (strcmp(argv[i], "--operation") == 0) {
            options.operation = argv[++i];
        } else if (strcmp(argv[i], "--format") == 0) {
            options.format = argv[++i];
        } else if (strcmp(argv[i], "--size") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed == 0 || parsed > SIZE_MAX) {
                fprintf(stderr, "invalid --size\n");
                return 2;
            }
            options.size = (size_t) parsed;
            options.size_set = 1;
        } else if (strcmp(argv[i], "--aad-size") == 0) {
            if (parse_u64(argv[++i], &parsed) != 0 || parsed > SIZE_MAX) {
                fprintf(stderr, "invalid --aad-size\n");
                return 2;
            }
            options.aad_size = (size_t) parsed;
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
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if (strcmp(options.operation, "all") != 0 && strcmp(options.operation, "seal") != 0 &&
        strcmp(options.operation, "open") != 0) {
        fprintf(stderr, "--operation must be seal, open, or all\n");
        return 2;
    }
    if (strcmp(options.format, "jsonl") != 0 && strcmp(options.format, "text") != 0) {
        fprintf(stderr, "--format must be jsonl or text\n");
        return 2;
    }

    info = ofb_backend_info();
    for (algorithm_index = 0; algorithm_index < info->algorithm_count; algorithm_index++) {
        const char *algorithm = info->algorithms[algorithm_index];
        if (!algorithm_selected(&options, algorithm)) {
            continue;
        }
        for (size_index = 0; size_index < (options.size_set ? 1 : 3); size_index++) {
            size_t size = options.size_set ? options.size : default_sizes[size_index];
            if (strcmp(options.operation, "all") == 0 || strcmp(options.operation, "seal") == 0) {
                if (run_case(&options, algorithm, OFB_SEAL, size) != 0) return 1;
            }
            if (strcmp(options.operation, "all") == 0 || strcmp(options.operation, "open") == 0) {
                if (run_case(&options, algorithm, OFB_OPEN, size) != 0) return 1;
            }
        }
    }
    if (strcmp(options.algorithm, "all") != 0) {
        for (algorithm_index = 0; algorithm_index < info->algorithm_count; algorithm_index++) {
            if (strcmp(options.algorithm, info->algorithms[algorithm_index]) == 0) return 0;
        }
        fprintf(stderr, "unsupported algorithm: %s\n", options.algorithm);
        return 2;
    }
    return 0;
}

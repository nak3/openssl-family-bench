# {Open|Libre|Boring}SSL benchmark

A simple benchmark of common symmetric primitives.

## Extensible benchmark runner

`ofb-openssl` is the new benchmark runner. It currently measures AEAD seal and
open operations for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. The runner,
timer, result formatting, and crypto backend are separate so that LibreSSL,
BoringSSL, AWS-LC, and wolfSSL can be built as separate executables without
loading libraries with conflicting OpenSSL-compatible symbols into one process.

### Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The benchmark build must not use AddressSanitizer or UndefinedBehaviorSanitizer.
Use a separate debug build when checking memory safety.

### Run

Run the default matrix (three algorithms, seal/open, and 64/1024/16384-byte
messages):

```sh
./build/ofb-openssl
```

Run one short human-readable case:

```sh
./build/ofb-openssl \
  --algorithm AES-128-GCM \
  --operation seal \
  --size 16384 \
  --samples 7 \
  --sample-ms 250 \
  --format text
```

The default output is JSON Lines, with one object per raw sample. Keep raw
samples rather than only an aggregate so that medians, percentiles, and plots
can be regenerated later.

### Measurement semantics

- Key creation, buffer allocation, and correctness checks are outside the timed
  region.
- Each timed operation includes cipher reinitialization, AAD processing,
  payload processing, finalization, and authentication-tag handling.
- The same prepared key and nonce are intentionally reused to isolate primitive
  operation cost. This is a benchmark fixture and is not safe usage for real
  encryption.
- The runner calibrates the iteration count to the requested sample duration.
- Seal and open, and in the future key generation and protocol operations, are
  reported as separate cases.

Use `./build/ofb-openssl --help` for all options and `--list` for the algorithms
provided by the linked backend.

### TLS 1.3

The TLS runner connects an in-process client and server with a memory BIO pair.
It measures full handshakes and application-data transfer without kernel socket
or network latency:

```sh
./build/ofb-openssl-tls \
  --benchmark handshake \
  --cipher TLS_AES_128_GCM_SHA256 \
  --samples 7 \
  --sample-ms 250 \
  --format text

./build/ofb-openssl-tls \
  --benchmark transfer \
  --cipher TLS_AES_128_GCM_SHA256 \
  --size 16384 \
  --samples 7 \
  --sample-ms 250 \
  --format text
```

`handshake` includes creating the client/server SSL objects, memory BIOs, the
TLS 1.3 state machine, key exchange, certificate signature, and key schedule.
The SSL contexts and certificate parsing stay outside the timed region.
`transfer` reuses a connection established outside the timed region and
measures client-to-server `SSL_write`/`SSL_read` processing. The bundled
certificate and private key are public test fixtures and must never be used by
a real server.

### LibreSSL

Build LibreSSL as a separate executable and use its generated CMake package:

```sh
cmake -S . -B build-libressl \
  -DCMAKE_BUILD_TYPE=Release \
  -DOFB_BACKEND=LIBRESSL \
  -DLibreSSL_DIR=/path/to/libressl/build
cmake --build build-libressl --parallel
ctest --test-dir build-libressl --output-on-failure
./build-libressl/ofb-libressl --format text
./build-libressl/ofb-libressl-tls --format text
```

Always use a different build directory for each backend. This prevents CMake's
cached include and library paths from accidentally mixing OpenSSL and LibreSSL.

#### Source and patch under test

CI checks out the official LibreSSL Portable `master` branch and runs its
`autogen.sh`. That script synchronizes the current OpenBSD `master` sources and
generates the portable source tree needed by the Linux runners. The workflow
records both the LibreSSL Portable and OpenBSD source commit IDs in the job
summary so a run can be reproduced even though the branches move.

The workflow builds two copies from that same generated source on the same
runner:

- `libressl`: unmodified OpenBSD `master` baseline
- `libressl-patched`: the same `master` revision with
  `patches/libressl/direct-tls13-record-header.patch` applied

An OpenBSD tree patch normally names files below `lib/libssl/`; the corresponding
LibreSSL Portable path is `ssl/`. Port the file paths and any platform-specific
context before putting a patch in `patches/libressl/`. The workflow applies the
patch with `patch -p1`, so a checked-in patch should use paths such as
`a/ssl/tls13_record.c` and `b/ssl/tls13_record.c`.

To test a different change, replace the checked-in patch, confirm that it applies
to the current LibreSSL development source, and push the branch or open a pull
request. The Actions summary reports `Patched / baseline`; values above 1.0 are
faster. Raw samples for both builds remain in the LibreSSL artifact.

### GitHub Actions

The `Benchmark` workflow runs natively on both x86_64 (`ubuntu-24.04`) and
ARM64 (`ubuntu-24.04-arm`) GitHub-hosted runners. On each architecture it
downloads and verifies the official OpenSSL 3.5.7 LTS release, then builds it
from source as static libraries. It does not use Ubuntu's `libssl-dev`. Both
baseline and patched LibreSSL are built from the current official LibreSSL
Portable/OpenBSD development branches. CI then runs the complete AEAD and TLS
1.3 matrices with three 100 ms samples per case and uploads the raw JSON Lines
files as workflow artifacts for 14 days.

The OpenSSL version and SHA-256 are declared in the workflow's top-level `env`
section. `LIBRESSL_REF` selects the LibreSSL Portable development branch; its
`OPENBSD_BRANCH` file selects the corresponding OpenBSD branch.
The workflow runs for pushes, pull requests, and manual dispatches.

Each backend job publishes a Markdown table to its GitHub Actions Job Summary.
A final `OpenSSL vs LibreSSL summary` job shows median results side by side,
including the OpenSSL/baseline and patched/baseline ratios, so the common results
can be inspected without downloading artifacts. The artifacts remain available
for raw-sample analysis. Results are grouped by the `architecture` field and
ratios are only calculated between backends running on the same architecture.
Do not interpret the absolute x86_64/ARM64 difference as an ISA-only comparison:
the hosted runners also use different physical CPUs and may have different
clock, cache, and virtualization characteristics.

GitHub-hosted runners are shared and their CPU performance varies between runs.
Treat these artifacts as build/correctness evidence and exploratory benchmark
data, not as a stable performance-regression threshold. Use a pinned
self-hosted runner when reproducible performance comparisons are required.

#### perf profiling

Use **Run workflow** on the dedicated `Crypto Profile` workflow to start separate
x86_64 and ARM64 profiling jobs. The workflow must exist on the repository's
default branch before GitHub exposes its **Run workflow** button; after that,
the branch selector can run it against `dev`. These jobs build OpenSSL, baseline
LibreSSL, and the patched LibreSSL with `-O3`, debug symbols, and frame pointers.

The profile matrix covers:

- all AEAD workloads: AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305;
- AES-128/256-CBC encrypt/decrypt, SHA-256/512, and HMAC-SHA256;
- TLS 1.3 handshake and transfer for all three supported cipher suites;
- patched LibreSSL TLS workloads, where the record-header patch can affect the
  call profile directly.

The regular `Benchmark` workflow remains separate and does not show skipped
profiling placeholders on pushes or pull requests.

Each profiling Job Summary starts with OpenSSL/LibreSSL and patched/baseline
comparison tables. It reports a quick median ratio by workload and per-case
throughput or operation counts; higher ratios favor the numerator. Because these
measurements use instrumented binaries, use the regular `Benchmark` workflow for
final performance numbers. Detailed hardware or software counters and text bar
charts for the hottest symbols are grouped by architecture, workload category,
and backend in collapsed sections. The corresponding artifact contains the
captured benchmark JSON, CSV counters, full text reports, and `perf.data`
recordings for local `perf report` or `perf annotate` analysis.
Some hosted runner PMUs support counting but not sampling interrupts on either
architecture. In that case the workflow keeps the `perf stat` counter
visualization and automatically uses a separate `gprof`-instrumented executable
and crypto libraries rebuilt with `gprof` instrumentation for function-level
hotspots. Hand-written assembly remains visible to statistical sampling, but it
does not receive compiler-inserted `gprof` call hooks.
The attempted `perf` event errors, raw `gmon` data, exact fallback executables,
and executable SHA-256 digests are preserved in the artifact. The workflow
checks for profiling hooks in both the executables and `libcrypto.a` before it
runs any profiles. It also supplies `gprof` with an external `nm` symbol table
so optimized local functions such as GCC's `*.part.N` clones are not attributed
to the preceding global symbol. Implausible ChaCha20 symbols are still flagged
as possible gprof symbol misattribution instead of being presented without
qualification.
Because `gprof` and `perf` use different collection mechanisms, compare hotspot
shapes within the same architecture/profiler rather than comparing their
percentages directly.
Profiling is opt-in because sampling and debug metadata can perturb timing; its
numbers are intentionally kept separate from the regular benchmark summary.

[Source code](cryptobench.c)

Benchmarked on a [Scaleway PRO 2](https://www.scaleway.com/en/virtual-instances/pro2/) instance (AMD 3rd Gen EPYC™ 7003).

* OpenSSL 3.0.2 (Ubuntu Jammy package)
* OpenSSL 1.1.1q
* LibreSSL 3.5.3
* BoringSSL b819f7e9392d25db6705a6bd3c92be3bb91775e2

Inputs have a 13 bytes of additional data in order to mimic typical TLS messages.

## Results

X axis is the block size.

Y axis is the throughput in Mib/s. Higher is better.

![AES-128-GCM](img/aes-128-gcm.png)

![AES-256-GCM](img/aes-256-gcm.png)

![AES-128-CBC](img/aes-128-cbc.png)

![AES-256-CBC](img/aes-256-cbc.png)

## Key exchange

ECDH over p256 and p384 ([Source code](cryptobench-ecdh.c))

![ECDH over p256 and p384 results](img/ecdh.png)

## RSA

### RSA signature ([Source code](cryptobench-rsa.c))

![RSA signature results](img/rsa.png)

### RSA verification ([Source code](cryptobench-rsa-verification.c))

![RSA verification results](img/rsa-verification.png)

## Comparing BoringSSL AEADs

[Source code](cryptobench-aegis.c), linked against BoringSSL with [AEGIS-128L](https://github.com/jedisct1/boringssl/tree/aegis) support.

Uses BoringSSL's dedicated AEAD API. Higher is better.

![BoringSSL benchmark](img/boring-aeads.png)

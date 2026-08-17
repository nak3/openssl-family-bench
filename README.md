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
```

Always use a different build directory for each backend. This prevents CMake's
cached include and library paths from accidentally mixing OpenSSL and LibreSSL.

### GitHub Actions

The `Benchmark` workflow builds and tests OpenSSL and LibreSSL independently on
Ubuntu. It then runs the complete AEAD matrix with three 100 ms samples per
case and uploads the raw JSON Lines files as workflow artifacts for 14 days.
The workflow runs for pushes, pull requests, and manual dispatches.

GitHub-hosted runners are shared and their CPU performance varies between runs.
Treat these artifacts as build/correctness evidence and exploratory benchmark
data, not as a stable performance-regression threshold. Use a pinned
self-hosted runner when reproducible performance comparisons are required.

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

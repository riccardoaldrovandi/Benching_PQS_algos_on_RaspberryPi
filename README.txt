README.md
PQC Benchmark Suite

Benchmarking Post-Quantum and Classical Cryptography (KEM, Signatures, Hash, KDF, Symmetric) on Raspberry Pi

This project provides a modular C-based benchmarking framework designed to evaluate and compare Post-Quantum Cryptography (PQC) algorithms and traditional/classical algorithms across different Raspberry Pi architectures.
It is engineered to run efficiently on RPi 1 / 3 / 4 / 5, supporting both 32-bit and 64-bit OS installations.

The framework measures:

Execution time (ns, µs)

CPU cycles

Instructions retired

L1 cache misses

Memory usage

CSV-formatted logs for data analysis

It integrates:

liboqs (all PQC KEMs & signatures)

OpenSSL 3 (classical hashes, HMAC, CMAC, HKDF, SHAKE, BLAKE2)

PAPI (performance counters)

ASCON implementations for lightweight hashing and AEAD

Adjustable benchmarking modules (KEM, Sign, Verify, Encaps, Decaps, Hash, KDF)

1. Algorithm Overview

This framework benchmarks two distinct classes of algorithms:

A. Post-Quantum Algorithms (PQS)

Provided by liboqs, based on NIST PQC standardization.

PQC KEMs (Key Encapsulation Mechanisms)

ML-KEM (Kyber) – NIST standard

ML-KEM-512

ML-KEM-768

ML-KEM-1024

BIKE

HQC

Classic McEliece

FrodoKEM (larger, reference-style KEM)

Others enabled by liboqs depending on build flags

PQC Digital Signatures

ML-DSA (Dilithium) – NIST standard

ML-DSA-44

ML-DSA-65

ML-DSA-87

Falcon

SPHINCS+

PQC algorithms are designed to remain secure even against quantum adversaries (Shor & Grover).

B. Classical / Traditional Algorithms (used as baselines)

These algorithms are NOT PQ-safe, but serve as reference metrics to understand performance differences.

Classical Hash Functions

SHA-256

SHA-384

SHA-512

BLAKE2b-512

ASCON-Hash (lightweight competitor in NIST LWC)

Classical KDFs (Key Derivation Functions)

HKDF-SHA256

HKDF-SHA384

HKDF-SHA512

HMAC-SHA256-based KDF

CMAC-AES256-based KDF

SHAKE128/256-based KDF (XOF, used also in some PQC schemes)

Classical Signatures / Key Exchange (OpenSSL)

(Optional: not the main focus but can be benchmarked if added)

ECDSA

ECDH (X25519) – included in your suite via bench_x25519_ecdh()

These help you quantify:
"How expensive is PQC compared to traditional crypto on low-power ARM hardware?"

2. Features

Benchmarks all PQC KEMs and signatures available in liboqs

Benchmarks reference classical algorithms (hashes, KDFs)

Unified CSV output for plotting & analysis

Architecture-aware optimization (automatically switches opt32 ↔ opt64)

Automatic environment setup for RPi via setup_rpi_env.sh

Clean and modular code structure

PAPI-based hardware counter measurements

Fully portable across Raspberry Pi versions

3. Repository Structure
src/
   bench_main.c
   bench_hash.c
   bench_kdf.c
   bench_kem.c
   bench_kem_keygen.c
   bench_kem_encaps.c
   bench_kem_decaps.c
   bench_sign.c
   bench_verify.c
   kem_buffers.c
   util_csv.c
   profiling.c
   papi_util.c
third_party/
   ascon/
       crypto_hash/asconhash256/opt32/  (or opt64/)
       crypto_aead/asconaead128/opt32/  (or opt64/)
Makefile
setup_rpi_env.sh
README.md

4. Automatic Environment Setup

Run:

chmod +x setup_rpi_env.sh
./setup_rpi_env.sh


The script performs:

✔ OS architecture detection

ARM32 → switch all /opt64/ to /opt32/

ARM64 → switch all /opt32/ to /opt64/

✔ Installation of system dependencies

(build-essential, cmake, libssl-dev, git, pkg-config, autoconf, automake, libtool)

✔ Automatic installation of PAPI from GitHub

Built into /usr/local/.

✔ Automatic installation of liboqs with ALL algorithms enabled
-DOQS_ENABLE_KEM=ON
-DOQS_ENABLE_SIG=ON
-DOQS_MINIMAL_BUILD=OFF
-DOQS_USE_OPENSSL=ON

✔ Automatic Makefile patching

removes hardcoded paths

ensures /usr/local/include + /usr/local/lib are used

✔ Architecture-specific ASCON optimization fix

Automatically adjusts all opt32/opt64 source paths.

✔ Linker test for liboqs + PAPI
5. Build Instructions
make clean
make


Produces:

./pqc_bench

6. Running Benchmarks
Benchmark all PQC algorithms
./pqc_bench --run-all --runs 100 --csv results.csv

List available algorithms
./pqc_bench --list

Benchmark a specific PQC KEM
./pqc_bench --kem ML-KEM-768 --runs 200

Benchmark a classical hash/KDF
./pqc_bench --kdf HKDF-SHA256 --runs 500
./pqc_bench --hash ASCON-Hash --runs 300

Benchmark classical ECDH (baseline)
./pqc_bench --ecdh --runs 200

7. Architecture Notes
Raspberry Pi OS 32-bit (armhf, armv6, armv7)

opt32 ASCON implementations

liboqs compiled for 32-bit

lower memory footprint

Raspberry Pi OS 64-bit (arm64)

opt64 ASCON implementations

full 64-bit liboqs builds

faster performance on Pi 4 / Pi 5

The setup script automatically handles these transitions.

8. Troubleshooting
❌ Undefined reference to kem_buffers_init

Solution: ensure src/kem_buffers.c is included in the Makefile.
(Already solved in latest version.)

❌ OpenSSL EVP_MAC_final type mismatch

Resolved by replacing EVP_MAC with classical HMAC/CMAC APIs.

❌ "liboqs not found" during linking

Run:

sudo ldconfig


Ensure:

/usr/local/lib/liboqs.so


exists.

❌ PAPI not initializing

Run:

papi_avail


If empty → installation failed → rerun setup script.

9. Author

Riccardo Aldrovandi
PQC & Embedded Systems Research
Raspberry Pi Post-Quantum Benchmarking Project

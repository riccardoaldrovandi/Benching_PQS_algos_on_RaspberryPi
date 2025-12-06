// bench_hash.c
// Benchmarking di funzioni di hash con profiling PAPI
#include "bench_hash.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "benching.h"

// ---- Ascon-Hash256 (opt32) ----
#include "../third_party/ascon/crypto_hash/asconhash256/opt32/api.h"
#include "../third_party/ascon/crypto_hash/asconhash256/opt32/crypto_hash.h"  // Qui includi il nuovo header

void bench_hash_generic(
    const char *alg_name,
    void (*hash_func)(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len),
    size_t msg_len,
    size_t out_len,
    int runs,
    const char *csv_path
) {
    uint8_t *msg = malloc(msg_len);
    uint8_t *out = malloc(out_len);
    if (!msg || !out) {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }

    uint32_t seed = 0xDEADBEEF;
    for (size_t i = 0; i < msg_len; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        msg[i] = (uint8_t)(seed & 0xFF);
    }

     FILE *csv = init_benching(csv_path);
    // warmup
    hash_func(msg, msg_len, out, out_len);

    for (int i = 0; i < runs; i++) {
        int event_set;
        uint64_t start_time;

       start_benching(&event_set, &start_time);
	hash_func(msg, msg_len, out, out_len);
       stop_benching(csv, i, msg_len, alg_name, event_set, start_time);
    }
    destroy_benching(csv);
    free(msg);
    free(out);
}



// ===============================
// Implementazioni specifiche
// ===============================

// --- SHA-256 (OpenSSL) ---
// Nuova versione con EVP
void hash_sha256(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len) {
    if (out_len < SHA256_DIGEST_LENGTH) { 
        fprintf(stderr, "Output buffer too small for SHA-256\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    // Inizializza l'algoritmo SHA256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        exit(EXIT_FAILURE);
    }

    unsigned int len = out_len;
    if (EVP_DigestFinal_ex(ctx, out, &len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(ctx);
}



// Funzione per SHA3-256 (OpenSSL)
void hash_sha3_256(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len) {
    if (out_len < SHA256_DIGEST_LENGTH) {  // SHA3-256 è 32 byte
        fprintf(stderr, "Output buffer too small for SHA3-256\n");
        exit(EXIT_FAILURE);
    }

    // Usa EVP per SHA3-256
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    // Inizializza SHA3-256
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        exit(EXIT_FAILURE);
    }

    unsigned int len = out_len;
    if (EVP_DigestFinal_ex(ctx, out, &len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(ctx);
}



// --- Ascon-Hash256 (asconhash256 / opt32) ---

static void hash_ascon_hash256(const uint8_t *msg, size_t msg_len,
                               uint8_t *out, size_t out_len) {
    // CRYPTO_BYTES definito in api.h (32)
    if (out_len < CRYPTO_BYTES) {
        fprintf(stderr, "Output buffer too small for Ascon-Hash256\n");
        exit(EXIT_FAILURE);
    }

    // API reale: int crypto_hash(unsigned char *out,
    //                            const unsigned char *in,
    //                            unsigned long long inlen);
    int r = crypto_hash(out, msg, (unsigned long long)msg_len);
    if (r != 0) {
        fprintf(stderr, "crypto_hash() (Ascon-Hash256) failed, ret=%d\n", r);
        exit(EXIT_FAILURE);
    }
}

// ===============================
// Funzioni esposte al resto del progetto
// ===============================

void bench_sha256(size_t msg_len, int runs, const char *csv_path) {
    bench_hash_generic("SHA-256", hash_sha256, msg_len,
                       SHA256_DIGEST_LENGTH, runs, csv_path);
}

void bench_sha3_256(size_t msg_len, int runs, const char *csv_path) {
    // SHA3-256 produce 32 byte di digest
    bench_hash_generic("SHA3-256", hash_sha3_256, msg_len,
                       32, runs, csv_path);
}

void bench_ascon_hash256(size_t msg_len, int runs, const char *csv_path) {
    bench_hash_generic("Ascon-Hash256", hash_ascon_hash256, msg_len,
                       CRYPTO_BYTES, runs, csv_path);
}

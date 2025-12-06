#ifndef BENCH_HASH_H
#define BENCH_HASH_H

#include <stdint.h>
#include <stddef.h>

// Dichiarazione di bench_hash_generic
void bench_hash_generic(
    const char *alg_name,
    void (*hash_func)(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len),
    size_t msg_len,
    size_t out_len,
    int runs,
    const char *csv_path
);

// Dichiarazioni delle altre funzioni per il benchmarking specifico
void bench_sha256(size_t msg_len, int runs, const char *csv_path);
void bench_sha3_256(size_t msg_len, int runs, const char *csv_path);
void bench_ascon_hash256(size_t msg_len, int runs, const char *csv_path);

#endif // BENCH_HASH_H

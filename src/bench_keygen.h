// bench_keygen.h
#ifndef BENCH_KEYGEN_H
#define BENCH_KEYGEN_H

#include <stddef.h>
#include <stdint.h>

/**
 * Callback generica per keygen:
 * deve generare (pk, sk) nei buffer passati.
 * Ritorna 0 su successo, !=0 su errore.
 */
typedef int (*keygen_func_t)(uint8_t *pk, size_t pk_len,
                             uint8_t *sk, size_t sk_len);

/**
 * Benchmark generico per keygen con PAPI + CSV.
 *
 * - alg_name: nome algoritmo (es. "ML-DSA-44")
 * - keygen  : funzione di keygen
 * - pk_len  : lunghezza pk in byte
 * - sk_len  : lunghezza sk in byte
 * - runs    : numero di iterazioni
 * - csv_path: path del file CSV
 */
void bench_keygen_generic(const char *alg_name,
                          keygen_func_t keygen,
                          size_t pk_len,
                          size_t sk_len,
                          int runs,
                          const char *csv_path);

/* Wrapper specifici per ogni algoritmo che vuoi supportare nel main. */
void bench_mldsa44_keygen(int runs, const char *csv_path);
void bench_mldsa65_keygen(int runs, const char *csv_path);
void bench_falcon512_keygen(int runs, const char *csv_path);

/* NUOVI wrapper */
void bench_mldsa87_keygen(int runs, const char *csv_path);
void bench_falcon1024_keygen(int runs, const char *csv_path);
void bench_ed25519_keygen(int runs, const char *csv_path);

#endif // BENCH_KEYGEN_H

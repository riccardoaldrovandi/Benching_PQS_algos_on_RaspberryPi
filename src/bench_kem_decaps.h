// src/bench_kem_decaps.h
#ifndef BENCH_KEM_DECAPS_H
#define BENCH_KEM_DECAPS_H

/**
 * Benchmark della sola decapsulation per un KEM liboqs.
 * Vengono generati pk/sk e un ciphertext valido una volta fuori dal loop,
 * poi si misura solo OQS_KEM_decaps.
 *
 * @param alg_name Nome dell'algoritmo OQS (es. "ML-KEM-512").
 * @param runs     Numero di ripetizioni.
 * @param csv_path Path al file CSV.
 * @return 0 su successo, -1 su errore.
 */
int bench_kem_decaps(const char *alg_name, int runs, const char *csv_path);

#endif // BENCH_KEM_DECAPS_H

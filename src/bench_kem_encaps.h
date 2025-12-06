// src/bench_kem_encaps.h
#ifndef BENCH_KEM_ENCAPS_H
#define BENCH_KEM_ENCAPS_H

/**
 * Benchmark della sola encapsulation per un KEM liboqs.
 * Viene generata una keypair una volta fuori dal loop,
 * poi si misura solo OQS_KEM_encaps.
 *
 * @param alg_name Nome dell'algoritmo OQS (es. "ML-KEM-512").
 * @param runs     Numero di ripetizioni.
 * @param csv_path Path al file CSV.
 * @return 0 su successo, -1 su errore.
 */
int bench_kem_encaps(const char *alg_name, int runs, const char *csv_path);
#endif // BENCH_KEM_ENCAPS_H

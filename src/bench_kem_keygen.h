// src/bench_kem_keygen.h
#ifndef BENCH_KEM_KEYGEN_H
#define BENCH_KEM_KEYGEN_H

/**
 * Esegue il benchmark della sola keygen per un KEM.
 *
 * @param alg_name  Nome dell'algoritmo (es. "ML-KEM-512")
 * @param runs      Numero di ripetizioni
 * @param csv_path  Path del file CSV dove loggare i risultati (può essere NULL se non logghi)
 * @return 0 su successo, -1 su errore
 */
int bench_kem_keygen(const char *alg_name, int runs, const char *csv_path);

int bench_x25519_ecdh(int runs, const char *csv_path);

#endif // BENCH_KEM_KEYGEN_H

// bench_sign.h
#ifndef BENCH_SIGN_H
#define BENCH_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "bench_keygen.h"  // per keygen_func_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Tipo generico di funzione di firma.
 *
 * msg / msg_len  : messaggio da firmare
 * sig / sig_len  : buffer firma + lunghezza in ingresso (max), in uscita lunghezza effettiva
 * sk / sk_len    : secret key usata per la firma
 *
 * Ritorna 0 in caso di successo, !=0 in caso di errore.
 */
typedef int (*sign_func_t)(const uint8_t *msg, size_t msg_len,
                           uint8_t *sig, size_t *sig_len,
                           const uint8_t *sk, size_t sk_len);

/**
 * Benchmark generico per la firma:
 *  - genera una coppia pk/sk con keygen() (una sola volta, fuori dal timing),
 *  - genera un messaggio di lunghezza msg_len,
 *  - esegue 'runs' firme con sign(), misurando con benching.h
 *  - salva i risultati nel CSV csv_path.
 *
 * Il campo "msg_len" nel CSV è msg_len.
 */
void bench_sign_generic(const char *alg_name,
                        sign_func_t sign,
                        keygen_func_t keygen,
                        size_t msg_len,
                        size_t pk_len,
                        size_t sk_len,
                        size_t sig_len,
                        int runs,
                        const char *csv_path);

/* Wrapper per gli algoritmi specifici (stesso stile di bench_keygen.c) */

void bench_mldsa44_sign(int runs, size_t msg_len, const char *csv_path);
void bench_mldsa65_sign(int runs, size_t msg_len, const char *csv_path);
void bench_mldsa87_sign(int runs, size_t msg_len, const char *csv_path);
void bench_falcon512_sign(int runs, size_t msg_len, const char *csv_path);
void bench_falcon1024_sign(int runs, size_t msg_len, const char *csv_path);
void bench_ed25519_sign(int runs, size_t msg_len, const char *csv_path);

#ifdef __cplusplus
}
#endif

#endif // BENCH_SIGN_H

// bench_verify.h
#ifndef BENCH_VERIFY_H
#define BENCH_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "bench_sign.h"   // per sign_func_t e keygen_func_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Tipo generico di funzione di verifica.
 *
 * msg / msg_len : messaggio originale
 * sig / sig_len : firma da verificare
 * pk / pk_len   : public key
 *
 * Ritorna 0 se la firma è valida, !=0 in caso di errore o firma invalida.
 */
typedef int (*verify_func_t)(const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len,
                             const uint8_t *pk, size_t pk_len);

/**
 * Benchmark generico per verify:
 *  - keygen(pk, sk) fuori dal timing
 *  - genera msg di lunghezza msg_len
 *  - sign(msg, sk) una volta, fuori dal timing
 *  - esegue 'runs' verifiche usando verify(), misurando con benching.h
 *  - salva nel CSV csv_path; il campo msg_len = msg_len
 */
void bench_verify_generic(const char *alg_name,
                          sign_func_t sign,
                          verify_func_t verify,
                          keygen_func_t keygen,
                          size_t msg_len,
                          size_t pk_len,
                          size_t sk_len,
                          size_t sig_len,
                          int runs,
                          const char *csv_path);

/* Wrapper per gli algoritmi specifici */

void bench_mldsa44_verify(int runs, size_t msg_len, const char *csv_path);
void bench_mldsa65_verify(int runs, size_t msg_len, const char *csv_path);
void bench_mldsa87_verify(int runs, size_t msg_len, const char *csv_path);
void bench_falcon512_verify(int runs, size_t msg_len, const char *csv_path);
void bench_falcon1024_verify(int runs, size_t msg_len, const char *csv_path);
void bench_ed25519_verify(int runs, size_t msg_len, const char *csv_path);

#ifdef __cplusplus
}
#endif

#endif // BENCH_VERIFY_H

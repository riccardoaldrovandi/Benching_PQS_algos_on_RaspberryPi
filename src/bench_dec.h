// bench_dec.h
#ifndef BENCH_DEC_H
#define BENCH_DEC_H

#include <stddef.h>
#include <stdint.h>
#include "bench_enc.h"  // per encrypt_func_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback generica per algoritmi AEAD decryption.
 *
 * key/key_len      : chiave
 * nonce/nonce_len  : nonce/iv
 * ct/ct_len        : ciphertext || tag (tag alla fine)
 * msg/msg_len[in/out] : plaintext (output)
 *
 * Ritorna 0 su successo (MAC ok), !=0 su errore/tag fail.
 */
typedef int (*decrypt_func_t)(
    const uint8_t *key,   size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *ct,    size_t ct_len,
    uint8_t *msg,         size_t *msg_len
);

/**
 * Benchmark generico per AEAD decryption:
 *  - genera key/nonce random
 *  - genera msg deterministico
 *  - esegue un'enc() fuori dal timing per ottenere ct+tag
 *  - warmup decrypt + check equality
 *  - loop di 'runs' decrypt misurando con benching.h
 */
void bench_decrypt_generic(
    const char *alg_name,
    encrypt_func_t enc,
    decrypt_func_t dec,
    size_t key_len,
    size_t nonce_len,
    size_t tag_len,
    size_t msg_len,
    int runs,
    const char *csv_path
);

/* Wrapper per algoritmi specifici */

void bench_aes256gcm_decrypt(int runs, size_t msg_len, const char *csv_path);
void bench_chacha20poly1305_decrypt(int runs, size_t msg_len, const char *csv_path);
void bench_ascon128_decrypt(int runs, size_t msg_len, const char *csv_path);

#ifdef __cplusplus
}
#endif

#endif // BENCH_DEC_H

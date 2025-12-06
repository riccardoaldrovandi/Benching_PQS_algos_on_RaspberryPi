// bench_enc.h
#ifndef BENCH_ENC_H
#define BENCH_ENC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Funzione di cifratura generica:
 *
 * key/key_len      : chiave
 * nonce/nonce_len  : nonce/iv
 * msg/msg_len      : plaintext
 * ct/ct_len        : ciphertext output
 *
 * Ritorna 0 su successo, !=0 su errore.
 */
typedef int (*encrypt_func_t)(
    const uint8_t *key,  size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len
);

/**
 * Bench generico:
 * - genera chiave e nonce random
 * - warmup
 * - misura ENCRYPT con benching.h
 */
void bench_encrypt_generic(
    const char *alg_name,
    encrypt_func_t enc,
    size_t key_len,
    size_t nonce_len,
    size_t tag_len,
    size_t msg_len,
    int runs,
    const char *csv_path
);

/* AES-256-GCM */
void bench_aes256gcm_encrypt(int runs, size_t msg_len, const char *csv_path);

/* ChaCha20-Poly1305 */
void bench_chacha20poly1305_encrypt(int runs, size_t msg_len, const char *csv_path);

/* Ascon-128 (opt32) */
void bench_ascon128_encrypt(int runs, size_t msg_len, const char *csv_path);

#ifdef __cplusplus
}
#endif

#endif

#ifndef BENCH_KDF_H
#define BENCH_KDF_H

#include <stddef.h>
#include <stdint.h>

/* ======================
 * Tipo callback KDF
 * ====================== */

typedef int (*kdf_func_t)(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len
);

/* ======================
 * Benchmark generico
 * ====================== */

/**
 * Misura SOLO la KDF.
 * - secret_len = "msg_len" per il CSV.
 * - out_len = lunghezza fissa (es. 32 byte) della key derivata.
 */
void bench_kdf_generic(
    const char *alg_name,
    kdf_func_t kdf,
    size_t secret_len,
    size_t out_len,
    int runs,
    const char *csv_path
);

/* ======================
 * Wrapper per KDF specifiche
 * secret_len = dimensione dell'input segreto
 * out_len è fissato a 32 byte (chiave a 256 bit)
 * ====================== */

void bench_hkdf_sha256   (size_t secret_len, int runs, const char *csv_path);
void bench_hkdf_sha384   (size_t secret_len, int runs, const char *csv_path);
void bench_hkdf_sha512   (size_t secret_len, int runs, const char *csv_path);

void bench_hmac_sha256   (size_t secret_len, int runs, const char *csv_path);
void bench_cmac_aes256   (size_t secret_len, int runs, const char *csv_path);

void bench_blake2b_kdf   (size_t secret_len, int runs, const char *csv_path);

void bench_shake128_kdf  (size_t secret_len, int runs, const char *csv_path);
void bench_shake256_kdf  (size_t secret_len, int runs, const char *csv_path);

#endif /* BENCH_KDF_H */

#include "bench_kdf.h"
#include "benching.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================
 * Benchmark KDF generico
 * ================================ */

void bench_kdf_generic(
    const char *alg_name,
    kdf_func_t kdf,
    size_t secret_len,
    size_t out_len,
    int runs,
    const char *csv_path)
{
    uint8_t *secret = malloc(secret_len);
    uint8_t *out    = malloc(out_len);

    if (!secret || !out) {
        fprintf(stderr, "malloc failed in bench_kdf_generic\n");
        free(secret);
        free(out);
        exit(EXIT_FAILURE);
    }

    /* segreto deterministico (no RNG per non "sporcare" il benchmark) */
    for (size_t i = 0; i < secret_len; i++) {
        secret[i] = (uint8_t)(i & 0xFF);
    }

    FILE *csv = init_benching(csv_path);

    /* warmup (non misurata) */
    if (kdf(secret, secret_len, out, out_len) != 0) {
        fprintf(stderr, "Warmup KDF failed for %s\n", alg_name);
        destroy_benching(csv);
        free(secret);
        free(out);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < runs; i++) {
        int event_set;
        uint64_t start_time;
        start_benching(&event_set, &start_time);

        if (kdf(secret, secret_len, out, out_len) != 0) {
            fprintf(stderr, "KDF failed for %s (run=%d)\n", alg_name, i);
            destroy_benching(csv);
            free(secret);
            free(out);
            exit(EXIT_FAILURE);
        }

        /* secret_len viene interpretato come "msg_len" nei CSV */
        stop_benching(csv, i, secret_len, alg_name, event_set, start_time);
    }

    destroy_benching(csv);
    free(secret);
    free(out);
}

/* ================================
 * Helper: HKDF (RFC 5869) generico
 * ================================ */

static int hkdf_extract(
    const EVP_MD *md,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm,  size_t ikm_len,
    uint8_t *prk, size_t *prk_len)
{
    size_t hash_len = (size_t)EVP_MD_size(md);

    if (salt == NULL || salt_len == 0) {
        /* salt = 0^HashLen se salt non è specificato */
        uint8_t zeros[EVP_MAX_MD_SIZE] = {0};
        salt = zeros;
        salt_len = hash_len;
    }

    unsigned int len = 0;
    if (!HMAC(md, salt, (int)salt_len, ikm, ikm_len, prk, &len)) {
        return -1;
    }
    *prk_len = (size_t)len;
    return 0;
}

static int hkdf_expand(
    const EVP_MD *md,
    const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len)
{
    size_t hash_len = (size_t)EVP_MD_size(md);
    if (okm_len > 255 * hash_len) {
        return -1;
    }

    uint8_t T[EVP_MAX_MD_SIZE];
    size_t T_len = 0;
    size_t pos = 0;
    uint8_t counter = 1;

    while (pos < okm_len) {
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) {
            return -1;
        }

        if (!HMAC_Init_ex(hctx, prk, (int)prk_len, md, NULL)) {
            HMAC_CTX_free(hctx);
            return -1;
        }

        if (T_len > 0) {
            if (!HMAC_Update(hctx, T, T_len)) {
                HMAC_CTX_free(hctx);
                return -1;
            }
        }

        if (!HMAC_Update(hctx, info, info_len)) {
            HMAC_CTX_free(hctx);
            return -1;
        }

        if (!HMAC_Update(hctx, &counter, 1)) {
            HMAC_CTX_free(hctx);
            return -1;
        }

        unsigned int len = 0;
        if (!HMAC_Final(hctx, T, &len)) {
            HMAC_CTX_free(hctx);
            return -1;
        }
#ifdef EVP_MAX_MD_SIZE
        if (len > EVP_MAX_MD_SIZE) {
            HMAC_CTX_free(hctx);
            return -1;
        }
#endif

        HMAC_CTX_free(hctx);

        T_len = (size_t)len;
        size_t to_copy = (okm_len - pos < T_len) ? (okm_len - pos) : T_len;
        memcpy(okm + pos, T, to_copy);
        pos += to_copy;
        counter++;
    }

    return 0;
}

static int hkdf_generic(
    const EVP_MD *md,
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    /* salt e info fissi per benchmarking */
    static const uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03 };
    static const uint8_t info[] = { 'K', 'D', 'F', '-', 't', 'e', 's', 't' };

    uint8_t prk[EVP_MAX_MD_SIZE];
    size_t prk_len = 0;

    if (hkdf_extract(md, salt, sizeof(salt), secret, secret_len, prk, &prk_len) != 0) {
        return -1;
    }

    if (hkdf_expand(md, prk, prk_len, info, sizeof(info), out, out_len) != 0) {
        OPENSSL_cleanse(prk, sizeof(prk));
        return -1;
    }

    /* opzionale: wipe prk */
    OPENSSL_cleanse(prk, sizeof(prk));
    return 0;
}

/* ================================
 * HKDF-SHA256 / SHA384 / SHA512
 * ================================ */

static int hkdf_sha256_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    return hkdf_generic(EVP_sha256(), secret, secret_len, out, out_len);
}

static int hkdf_sha384_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    return hkdf_generic(EVP_sha384(), secret, secret_len, out, out_len);
}

static int hkdf_sha512_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    return hkdf_generic(EVP_sha512(), secret, secret_len, out, out_len);
}

/* wrapper pubblici (out_len fisso 32 byte) */

void bench_hkdf_sha256(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("HKDF-SHA256", hkdf_sha256_cb,
                      secret_len, 32, runs, csv_path);
}

void bench_hkdf_sha384(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("HKDF-SHA384", hkdf_sha384_cb,
                      secret_len, 32, runs, csv_path);
}

void bench_hkdf_sha512(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("HKDF-SHA512", hkdf_sha512_cb,
                      secret_len, 32, runs, csv_path);
}

/* ================================
 * HMAC-SHA256 KDF semplice
 * ================================ */

static int hmac_sha256_kdf_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    static const uint8_t msg[] = {
        'H','M','A','C','-','K','D','F','-','t','e','s','t'
    };

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!HMAC(EVP_sha256(),
              secret, (int)secret_len,
              msg, sizeof(msg),
              digest, &dlen)) {
        return -1;
    }

    size_t to_copy = (out_len < (size_t)dlen) ? out_len : (size_t)dlen;
    memcpy(out, digest, to_copy);
    if (out_len > to_copy) {
        memset(out + to_copy, 0, out_len - to_copy);
    }

    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

void bench_hmac_sha256(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("HMAC-SHA256-KDF",
                      hmac_sha256_kdf_cb,
                      secret_len, 32, runs, csv_path);
}

/* ================================
 * AES-CMAC-256 KDF
 * ================================ */

static int cmac_aes256_kdf_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    /* Derivazione della chiave per AES-256 (SHA256 del secret) */
    uint8_t key[32];
    {
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        if (!EVP_Digest(secret, secret_len, digest, &dlen, EVP_sha256(), NULL)) {
            OPENSSL_cleanse(digest, sizeof(digest));
            return -1;
        }
        if (dlen < 32) {
            /* improbabile, ma per sicurezza */
            memset(key, 0, sizeof(key));
            memcpy(key, digest, dlen);
        } else {
            memcpy(key, digest, 32);
        }
        OPENSSL_cleanse(digest, sizeof(digest));
    }

    static const uint8_t msg[] = {
        'C','M','A','C','-','K','D','F','-','t','e','s','t'
    };

    uint8_t mac[EVP_MAX_BLOCK_LENGTH];
    size_t mac_len = 0;

    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }

    if (!CMAC_Init(ctx, key, sizeof(key), EVP_aes_256_cbc(), NULL)) {
        CMAC_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }

    if (!CMAC_Update(ctx, msg, sizeof(msg))) {
        CMAC_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }

    if (!CMAC_Final(ctx, mac, &mac_len)) {
        CMAC_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }

    CMAC_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));

    size_t to_copy = (out_len < mac_len) ? out_len : mac_len;
    memcpy(out, mac, to_copy);
    if (out_len > to_copy) {
        memset(out + to_copy, 0, out_len - to_copy);
    }

    OPENSSL_cleanse(mac, sizeof(mac));
    return 0;
}

void bench_cmac_aes256(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("CMAC-AES256-KDF",
                      cmac_aes256_kdf_cb,
                      secret_len, 32, runs, csv_path);
}

/* ================================
 * BLAKE2b-based KDF
 * ================================ */

static int blake2b_kdf_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    static const uint8_t label[] = {
        'B','L','A','K','E','2','-','K','D','F','-','t','e','s','t'
    };

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    int ret = -1;

    if (!EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL))
        goto cleanup;

    if (!EVP_DigestUpdate(ctx, secret, secret_len))
        goto cleanup;

    if (!EVP_DigestUpdate(ctx, label, sizeof(label)))
        goto cleanup;

    if (!EVP_DigestFinal_ex(ctx, digest, &dlen))
        goto cleanup;

    {
        size_t to_copy = (out_len < (size_t)dlen) ? out_len : (size_t)dlen;
        memcpy(out, digest, to_copy);
        if (out_len > to_copy) {
            memset(out + to_copy, 0, out_len - to_copy);
        }
    }

    ret = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(digest, sizeof(digest));
    return ret;
}

void bench_blake2b_kdf(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("BLAKE2b-KDF",
                      blake2b_kdf_cb,
                      secret_len, 32, runs, csv_path);
}

/* ================================
 * SHAKE128 / SHAKE256 based KDF
 * ================================ */

static int shake_kdf_generic(
    const EVP_MD *shake_md,
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int ret = -1;

    static const uint8_t label[] = {
        'S','H','A','K','E','-','K','D','F','-','t','e','s','t'
    };

    if (!EVP_DigestInit_ex(ctx, shake_md, NULL))
        goto cleanup;

    if (!EVP_DigestUpdate(ctx, secret, secret_len))
        goto cleanup;

    if (!EVP_DigestUpdate(ctx, label, sizeof(label)))
        goto cleanup;

    if (!EVP_DigestFinalXOF(ctx, out, out_len))
        goto cleanup;

    ret = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int shake128_kdf_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    return shake_kdf_generic(EVP_shake128(), secret, secret_len, out, out_len);
}

static int shake256_kdf_cb(
    const uint8_t *secret, size_t secret_len,
    uint8_t *out, size_t out_len)
{
    return shake_kdf_generic(EVP_shake256(), secret, secret_len, out, out_len);
}

void bench_shake128_kdf(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("SHAKE128-KDF",
                      shake128_kdf_cb,
                      secret_len, 32, runs, csv_path);
}

void bench_shake256_kdf(size_t secret_len, int runs, const char *csv_path)
{
    bench_kdf_generic("SHAKE256-KDF",
                      shake256_kdf_cb,
                      secret_len, 32, runs, csv_path);
}

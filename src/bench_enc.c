// bench_enc.c
#include "bench_enc.h"
#include "benching.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../third_party/ascon/crypto_aead/asconaead128/opt32/api.h"
#include "../third_party/ascon/crypto_aead/asconaead128/opt32/ascon.h"  // dentro opt32

/* ================================
 * Benchmark simmetrico generico
 * ================================ */

void bench_encrypt_generic(
    const char *alg_name,
    encrypt_func_t enc,
    size_t key_len,
    size_t nonce_len,
    size_t tag_len,
    size_t msg_len,
    int runs,
    const char *csv_path)
{
    uint8_t *key   = malloc(key_len);
    uint8_t *nonce = malloc(nonce_len);
    uint8_t *msg   = malloc(msg_len);
    uint8_t *ct    = malloc(msg_len + tag_len);

    if (!key || !nonce || !msg || !ct) {
        fprintf(stderr, "malloc failed in bench_encrypt_generic\n");
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        exit(EXIT_FAILURE);
    }

    /* random key e nonce */
    if (RAND_bytes(key, (int)key_len) != 1 ||
        RAND_bytes(nonce, (int)nonce_len) != 1) {
        fprintf(stderr, "RAND_bytes failed in bench_encrypt_generic\n");
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        exit(EXIT_FAILURE);
    }

    /* messaggio deterministico */
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i & 0xFF);
    }

    FILE *csv = init_benching(csv_path);

    /* warmup */
    size_t warm_ct_len = msg_len + tag_len;
    if (enc(key, key_len, nonce, nonce_len, msg, msg_len, ct, &warm_ct_len) != 0) {
        fprintf(stderr, "Warmup encrypt failed for %s\n", alg_name);
        destroy_benching(csv);
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < runs; i++) {
        int event_set;
        uint64_t start_time;
        start_benching(&event_set, &start_time);

        size_t ct_len = msg_len + tag_len;
        if (enc(key, key_len, nonce, nonce_len, msg, msg_len, ct, &ct_len) != 0) {
            fprintf(stderr, "Encrypt failed for %s (run=%d)\n", alg_name, i);
            destroy_benching(csv);
            free(key);
            free(nonce);
            free(msg);
            free(ct);
            exit(EXIT_FAILURE);
        }

        /* msg_len nel CSV = lunghezza plaintext */
        stop_benching(csv, i, msg_len, alg_name, event_set, start_time);
    }

    destroy_benching(csv);
    free(key);
    free(nonce);
    free(msg);
    free(ct);
}

/* =======================================
 * AES-256-GCM (OpenSSL EVP)
 * ======================================= */

static int aes256gcm_encrypt_cb(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len)
{
    (void)key_len;  /* lunghezza fissa: 32 */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) <= 0)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, ct, &len, msg, (int)msg_len) <= 0)
        goto cleanup;

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) <= 0)
        goto cleanup;

    ciphertext_len += len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) <= 0)
        goto cleanup;

    memcpy(ct + ciphertext_len, tag, 16);
    *ct_len = (size_t)(ciphertext_len + 16);

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void bench_aes256gcm_encrypt(int runs, size_t msg_len, const char *csv_path)
{
    bench_encrypt_generic(
        "AES-256-GCM",
        aes256gcm_encrypt_cb,
        32,  // key_len
        12,  // nonce_len
        16,  // tag_len
        msg_len,
        runs,
        csv_path
    );
}

/* =======================================
 * ChaCha20-Poly1305 (OpenSSL EVP)
 * ======================================= */

static int chacha20poly1305_encrypt_cb(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len)
{
    (void)key_len;  /* lunghezza fissa: 32 */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = -1;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) <= 0)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) <= 0)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, ct, &len, msg, (int)msg_len) <= 0)
        goto cleanup;

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) <= 0)
        goto cleanup;

    ciphertext_len += len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) <= 0)
        goto cleanup;

    memcpy(ct + ciphertext_len, tag, 16);
    *ct_len = (size_t)(ciphertext_len + 16);

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void bench_chacha20poly1305_encrypt(int runs, size_t msg_len, const char *csv_path)
{
    bench_encrypt_generic(
        "ChaCha20-Poly1305",
        chacha20poly1305_encrypt_cb,
        32,  // key
        12,  // nonce
        16,  // tag
        msg_len,
        runs,
        csv_path
    );
}

/* =======================================
 * ASCON-128 AEAD (opt32)
 * ======================================= */

static int ascon128_encrypt_cb(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len)
{
    (void)key_len;
    (void)nonce_len;

    /*
     * API (opt32):
     * int ascon_aead_encrypt(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
     *                        const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
     *                        const uint8_t* k);
     *
     * Noi memorizziamo:
     *   - ciphertext in ct[0 .. msg_len-1]
     *   - tag       in ct[msg_len .. msg_len+CRYPTO_ABYTES-1]
     */

    uint8_t *c = ct;
    uint8_t *t = ct + msg_len;

    if (ascon_aead_encrypt(
            t,            /* tag */
            c,            /* ciphertext */
            msg, (uint64_t)msg_len, /* plaintext */
            NULL, 0,      /* AD assente */
            nonce,        /* npub */
            key           /* key */
        ) != 0)
    {
        return -1;
    }

    *ct_len = msg_len + CRYPTO_ABYTES;
    return 0;
}

void bench_ascon128_encrypt(int runs, size_t msg_len, const char *csv_path)
{
    bench_encrypt_generic(
        "Ascon-128",
        ascon128_encrypt_cb,
        CRYPTO_KEYBYTES,
        CRYPTO_NPUBBYTES,
        CRYPTO_ABYTES,
        msg_len,
        runs,
        csv_path
    );
}

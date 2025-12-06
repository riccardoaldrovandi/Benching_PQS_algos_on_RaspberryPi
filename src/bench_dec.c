// bench_dec.c
#include "bench_dec.h"
#include "benching.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Ascon AEAD (stessa logica degli include in bench_enc.c)
#include "../third_party/ascon/crypto_aead/asconaead128/opt32/api.h"
#include "../third_party/ascon/crypto_aead/asconaead128/opt32/ascon.h"

/* ================================
 * Benchmark AEAD decryption generico
 * ================================ */

void bench_decrypt_generic(
    const char *alg_name,
    encrypt_func_t enc,
    decrypt_func_t dec,
    size_t key_len,
    size_t nonce_len,
    size_t tag_len,
    size_t msg_len,
    int runs,
    const char *csv_path)
{
    uint8_t *key    = malloc(key_len);
    uint8_t *nonce  = malloc(nonce_len);
    uint8_t *msg    = malloc(msg_len);
    uint8_t *ct     = malloc(msg_len + tag_len);
    uint8_t *decbuf = malloc(msg_len);

    if (!key || !nonce || !msg || !ct || !decbuf) {
        fprintf(stderr, "malloc failed in bench_decrypt_generic\n");
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        free(decbuf);
        exit(EXIT_FAILURE);
    }

    if (RAND_bytes(key, (int)key_len) != 1 ||
        RAND_bytes(nonce, (int)nonce_len) != 1) {
        fprintf(stderr, "RAND_bytes failed in bench_decrypt_generic\n");
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        free(decbuf);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i & 0xFF);
    }

    /* Encryption fuori dal timing per avere ct+tag validi */
    size_t ct_len = msg_len + tag_len;
    if (enc(key, key_len, nonce, nonce_len, msg, msg_len, ct, &ct_len) != 0) {
        fprintf(stderr, "Encrypt (pre-decrypt) failed for %s\n", alg_name);
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        free(decbuf);
        exit(EXIT_FAILURE);
    }

    /* Warmup decrypt + check correttezza */
    size_t warm_msg_len = msg_len;
    if (dec(key, key_len, nonce, nonce_len, ct, ct_len, decbuf, &warm_msg_len) != 0) {
        fprintf(stderr, "Decrypt warmup failed for %s (MAC error?)\n", alg_name);
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        free(decbuf);
        exit(EXIT_FAILURE);
    }
    if (warm_msg_len != msg_len || memcmp(decbuf, msg, msg_len) != 0) {
        fprintf(stderr, "Decrypt warmup produced wrong plaintext for %s\n", alg_name);
        free(key);
        free(nonce);
        free(msg);
        free(ct);
        free(decbuf);
        exit(EXIT_FAILURE);
    }

    FILE *csv = init_benching(csv_path);

    for (int i = 0; i < runs; i++) {
        int event_set;
        uint64_t start_time;
        start_benching(&event_set, &start_time);

        size_t out_len = msg_len;
        if (dec(key, key_len, nonce, nonce_len, ct, ct_len, decbuf, &out_len) != 0) {
            fprintf(stderr, "Decrypt failed for %s at run %d\n", alg_name, i);
            destroy_benching(csv);
            free(key);
            free(nonce);
            free(msg);
            free(ct);
            free(decbuf);
            exit(EXIT_FAILURE);
        }

        stop_benching(csv, i, msg_len, alg_name, event_set, start_time);
    }

    destroy_benching(csv);
    free(key);
    free(nonce);
    free(msg);
    free(ct);
    free(decbuf);
}

/* =======================================
 * AES-256-GCM decryption (OpenSSL)
 * ======================================= */

/* Encryption di supporto per preparare ct+tag */
static int aes256gcm_encrypt_for_dec(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len)
{
    (void)key_len;

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

static int aes256gcm_decrypt_cb(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *ct, size_t ct_len,
    uint8_t *msg, size_t *msg_len)
{
    (void)key_len;

    if (ct_len < 16) return -1;

    size_t ciphertext_len = ct_len - 16;
    const uint8_t *ciphertext = ct;
    const uint8_t *tag = ct + ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) <= 0)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
        goto cleanup;

    if (EVP_DecryptUpdate(ctx, msg, &len, ciphertext, (int)ciphertext_len) <= 0)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) <= 0)
        goto cleanup;

    {
        int len_final = 0;
        int f = EVP_DecryptFinal_ex(ctx, msg + len, &len_final);
        if (f <= 0)
            goto cleanup;  // tag fail
        *msg_len = (size_t)(len + len_final);
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void bench_aes256gcm_decrypt(int runs, size_t msg_len, const char *csv_path)
{
    bench_decrypt_generic(
        "AES-256-GCM",
        aes256gcm_encrypt_for_dec,
        aes256gcm_decrypt_cb,
        32,  // key_len
        12,  // nonce_len
        16,  // tag_len
        msg_len,
        runs,
        csv_path
    );
}

/* =======================================
 * ChaCha20-Poly1305 decryption (OpenSSL)
 * ======================================= */

static int chacha20poly1305_encrypt_for_dec(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len)
{
    (void)key_len;

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

static int chacha20poly1305_decrypt_cb(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *ct, size_t ct_len,
    uint8_t *msg, size_t *msg_len)
{
    (void)key_len;

    if (ct_len < 16) return -1;

    size_t ciphertext_len = ct_len - 16;
    const uint8_t *ciphertext = ct;
    const uint8_t *tag = ct + ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = -1;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) <= 0)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) <= 0)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
        goto cleanup;

    if (EVP_DecryptUpdate(ctx, msg, &len, ciphertext, (int)ciphertext_len) <= 0)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) <= 0)
        goto cleanup;

    {
        int len_final = 0;
        int f = EVP_DecryptFinal_ex(ctx, msg + len, &len_final);
        if (f <= 0)
            goto cleanup;  // tag fail
        *msg_len = (size_t)(len + len_final);
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void bench_chacha20poly1305_decrypt(int runs, size_t msg_len, const char *csv_path)
{
    bench_decrypt_generic(
        "ChaCha20-Poly1305",
        chacha20poly1305_encrypt_for_dec,
        chacha20poly1305_decrypt_cb,
        32,  // key
        12,  // nonce
        16,  // tag
        msg_len,
        runs,
        csv_path
    );
}

/* =======================================
 * ASCON-128 AEAD decryption (opt32)
 * ======================================= */

static int ascon128_encrypt_for_dec(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *ct, size_t *ct_len)
{
    (void)key_len;
    (void)nonce_len;

    uint8_t *c = ct;
    uint8_t *t = ct + msg_len;

    if (ascon_aead_encrypt(
            t,            /* tag */
            c,            /* ciphertext */
            msg, (uint64_t)msg_len,
            NULL, 0,      /* AD */
            nonce,        /* npub */
            key           /* key */
        ) != 0)
    {
        return -1;
    }

    *ct_len = msg_len + CRYPTO_ABYTES;
    return 0;
}

static int ascon128_decrypt_cb(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *ct, size_t ct_len,
    uint8_t *msg, size_t *msg_len)
{
    (void)key_len;
    (void)nonce_len;

    if (ct_len < CRYPTO_ABYTES) return -1;

    size_t clen = ct_len - CRYPTO_ABYTES;
    const uint8_t *c = ct;
    const uint8_t *t = ct + clen;

    if (ascon_aead_decrypt(
            msg,                 /* plaintext out */
            (uint8_t*)t,         /* tag */
            c, (uint64_t)clen,   /* ciphertext + length */
            NULL, 0,             /* AD */
            nonce,               /* npub */
            key                  /* key */
        ) != 0)
    {
        return -1;
    }

    *msg_len = clen;
    return 0;
}

void bench_ascon128_decrypt(int runs, size_t msg_len, const char *csv_path)
{
    bench_decrypt_generic(
        "Ascon-128",
        ascon128_encrypt_for_dec,
        ascon128_decrypt_cb,
        CRYPTO_KEYBYTES,
        CRYPTO_NPUBBYTES,
        CRYPTO_ABYTES,
        msg_len,
        runs,
        csv_path
    );
}
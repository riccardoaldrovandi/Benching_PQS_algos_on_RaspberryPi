// bench_verify.c
#include "bench_verify.h"
#include "benching.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* =============================
 * Benchmark generico per verify
 * ============================= */

void bench_verify_generic(const char *alg_name,
                          sign_func_t sign,
                          verify_func_t verify,
                          keygen_func_t keygen,
                          size_t msg_len,
                          size_t pk_len,
                          size_t sk_len,
                          size_t sig_len,
                          int runs,
                          const char *csv_path)
{
    uint8_t *pk  = malloc(pk_len);
    uint8_t *sk  = malloc(sk_len);
    uint8_t *msg = malloc(msg_len);
    uint8_t *sig = malloc(sig_len);

    if (!pk || !sk || !msg || !sig) {
        fprintf(stderr, "malloc failed in bench_verify_generic\n");
        free(pk);
        free(sk);
        free(msg);
        free(sig);
        exit(EXIT_FAILURE);
    }

    /* Keygen una volta fuori dal timing */
    if (keygen(pk, pk_len, sk, sk_len) != 0) {
        fprintf(stderr, "keygen failed in bench_verify_generic for %s\n", alg_name);
        free(pk);
        free(sk);
        free(msg);
        free(sig);
        exit(EXIT_FAILURE);
    }

    /* Messaggio deterministico */
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i & 0xFF);
    }

    /* Firma una volta (fuori dal timing) */
    size_t actual_sig_len = sig_len;
    if (sign(msg, msg_len, sig, &actual_sig_len, sk, sk_len) != 0) {
        fprintf(stderr, "sign (pre-verify) failed for %s\n", alg_name);
        free(pk);
        free(sk);
        free(msg);
        free(sig);
        exit(EXIT_FAILURE);
    }

    FILE *csv = init_benching(csv_path);

    /* Warmup verify */
    if (verify(msg, msg_len, sig, actual_sig_len, pk, pk_len) != 0) {
        fprintf(stderr, "verify warmup failed for %s\n", alg_name);
        destroy_benching(csv);
        free(pk);
        free(sk);
        free(msg);
        free(sig);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < runs; i++) {
        int event_set;
        uint64_t start_time;

        start_benching(&event_set, &start_time);

        if (verify(msg, msg_len, sig, actual_sig_len, pk, pk_len) != 0) {
            fprintf(stderr, "verify failed for %s at run %d\n", alg_name, i);
            destroy_benching(csv);
            free(pk);
            free(sk);
            free(msg);
            free(sig);
            exit(EXIT_FAILURE);
        }

        /* msg_len nel CSV */
        stop_benching(csv, i, msg_len, alg_name, event_set, start_time);
    }

    destroy_benching(csv);
    free(pk);
    free(sk);
    free(msg);
    free(sig);
}

/* =============================
 * Wrapper liboqs per algoritmi specifici
 * ============================= */

/* -------- ML-DSA-44 -------- */

static int mldsa44_keygen_for_verify(uint8_t *pk, size_t pk_len,
                                     uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-44");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-44) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key || sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for ML-DSA-44 pk/sk\n");
        return -1;
    }

    return OQS_SIG_keypair(sig, pk, sk);
}

static int mldsa44_sign_for_verify_cb(const uint8_t *msg, size_t msg_len,
                                      uint8_t *signature, size_t *signature_len,
                                      const uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-44");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-44) failed\n");
            return -1;
        }
    }

    if (sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for ML-DSA-44 sk\n");
        return -1;
    }
    if (*signature_len < sig->length_signature) {
        fprintf(stderr, "buffer too small for ML-DSA-44 signature\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_sign(sig,
                                 signature,
                                 signature_len,
                                 msg,
                                 msg_len,
                                 sk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

static int mldsa44_verify_cb(const uint8_t *msg, size_t msg_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *pk, size_t pk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-44");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-44) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key) {
        fprintf(stderr, "buffer too small for ML-DSA-44 pk\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_verify(sig,
                                   msg,
                                   msg_len,
                                   signature,
                                   signature_len,
                                   pk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

void bench_mldsa44_verify(int runs, size_t msg_len, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-44");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(ML-DSA-44) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len  = sig->length_public_key;
    size_t sk_len  = sig->length_secret_key;
    size_t sig_len = sig->length_signature;
    OQS_SIG_free(sig);

    bench_verify_generic("ML-DSA-44",
                         mldsa44_sign_for_verify_cb,
                         mldsa44_verify_cb,
                         mldsa44_keygen_for_verify,
                         msg_len,
                         pk_len,
                         sk_len,
                         sig_len,
                         runs,
                         csv_path);
}

/* -------- ML-DSA-65 -------- */

static int mldsa65_keygen_for_verify(uint8_t *pk, size_t pk_len,
                                     uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-65");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key || sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for ML-DSA-65 pk/sk\n");
        return -1;
    }

    return OQS_SIG_keypair(sig, pk, sk);
}

static int mldsa65_sign_for_verify_cb(const uint8_t *msg, size_t msg_len,
                                      uint8_t *signature, size_t *signature_len,
                                      const uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-65");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed\n");
            return -1;
        }
    }

    if (sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for ML-DSA-65 sk\n");
        return -1;
    }
    if (*signature_len < sig->length_signature) {
        fprintf(stderr, "buffer too small for ML-DSA-65 signature\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_sign(sig,
                                 signature,
                                 signature_len,
                                 msg,
                                 msg_len,
                                 sk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

static int mldsa65_verify_cb(const uint8_t *msg, size_t msg_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *pk, size_t pk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-65");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key) {
        fprintf(stderr, "buffer too small for ML-DSA-65 pk\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_verify(sig,
                                   msg,
                                   msg_len,
                                   signature,
                                   signature_len,
                                   pk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

void bench_mldsa65_verify(int runs, size_t msg_len, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len  = sig->length_public_key;
    size_t sk_len  = sig->length_secret_key;
    size_t sig_len = sig->length_signature;
    OQS_SIG_free(sig);

    bench_verify_generic("ML-DSA-65",
                         mldsa65_sign_for_verify_cb,
                         mldsa65_verify_cb,
                         mldsa65_keygen_for_verify,
                         msg_len,
                         pk_len,
                         sk_len,
                         sig_len,
                         runs,
                         csv_path);
}

/* -------- ML-DSA-87 -------- */

static int mldsa87_keygen_for_verify(uint8_t *pk, size_t pk_len,
                                     uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-87");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-87) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key || sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for ML-DSA-87 pk/sk\n");
        return -1;
    }

    return OQS_SIG_keypair(sig, pk, sk);
}

static int mldsa87_sign_for_verify_cb(const uint8_t *msg, size_t msg_len,
                                      uint8_t *signature, size_t *signature_len,
                                      const uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-87");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-87) failed\n");
            return -1;
        }
    }

    if (sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for ML-DSA-87 sk\n");
        return -1;
    }
    if (*signature_len < sig->length_signature) {
        fprintf(stderr, "buffer too small for ML-DSA-87 signature\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_sign(sig,
                                 signature,
                                 signature_len,
                                 msg,
                                 msg_len,
                                 sk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

static int mldsa87_verify_cb(const uint8_t *msg, size_t msg_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *pk, size_t pk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("ML-DSA-87");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(ML-DSA-87) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key) {
        fprintf(stderr, "buffer too small for ML-DSA-87 pk\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_verify(sig,
                                   msg,
                                   msg_len,
                                   signature,
                                   signature_len,
                                   pk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

void bench_mldsa87_verify(int runs, size_t msg_len, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-87");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(ML-DSA-87) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len  = sig->length_public_key;
    size_t sk_len  = sig->length_secret_key;
    size_t sig_len = sig->length_signature;
    OQS_SIG_free(sig);

    bench_verify_generic("ML-DSA-87",
                         mldsa87_sign_for_verify_cb,
                         mldsa87_verify_cb,
                         mldsa87_keygen_for_verify,
                         msg_len,
                         pk_len,
                         sk_len,
                         sig_len,
                         runs,
                         csv_path);
}

/* -------- Falcon-512 -------- */

static int falcon512_keygen_for_verify(uint8_t *pk, size_t pk_len,
                                       uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("Falcon-512");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(Falcon-512) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key || sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for Falcon-512 pk/sk\n");
        return -1;
    }

    return OQS_SIG_keypair(sig, pk, sk);
}

static int falcon512_sign_for_verify_cb(const uint8_t *msg, size_t msg_len,
                                        uint8_t *signature, size_t *signature_len,
                                        const uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("Falcon-512");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(Falcon-512) failed\n");
            return -1;
        }
    }

    if (sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for Falcon-512 sk\n");
        return -1;
    }
    if (*signature_len < sig->length_signature) {
        fprintf(stderr, "buffer too small for Falcon-512 signature\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_sign(sig,
                                 signature,
                                 signature_len,
                                 msg,
                                 msg_len,
                                 sk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

static int falcon512_verify_cb(const uint8_t *msg, size_t msg_len,
                               const uint8_t *signature, size_t signature_len,
                               const uint8_t *pk, size_t pk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("Falcon-512");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(Falcon-512) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key) {
        fprintf(stderr, "buffer too small for Falcon-512 pk\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_verify(sig,
                                   msg,
                                   msg_len,
                                   signature,
                                   signature_len,
                                   pk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

void bench_falcon512_verify(int runs, size_t msg_len, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("Falcon-512");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(Falcon-512) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len  = sig->length_public_key;
    size_t sk_len  = sig->length_secret_key;
    size_t sig_len = sig->length_signature;
    OQS_SIG_free(sig);

    bench_verify_generic("Falcon-512",
                         falcon512_sign_for_verify_cb,
                         falcon512_verify_cb,
                         falcon512_keygen_for_verify,
                         msg_len,
                         pk_len,
                         sk_len,
                         sig_len,
                         runs,
                         csv_path);
}

/* -------- Falcon-1024 -------- */

static int falcon1024_keygen_for_verify(uint8_t *pk, size_t pk_len,
                                        uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("Falcon-1024");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(Falcon-1024) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key || sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for Falcon-1024 pk/sk\n");
        return -1;
    }

    return OQS_SIG_keypair(sig, pk, sk);
}

static int falcon1024_sign_for_verify_cb(const uint8_t *msg, size_t msg_len,
                                         uint8_t *signature, size_t *signature_len,
                                         const uint8_t *sk, size_t sk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("Falcon-1024");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(Falcon-1024) failed\n");
            return -1;
        }
    }

    if (sk_len < sig->length_secret_key) {
        fprintf(stderr, "buffer too small for Falcon-1024 sk\n");
        return -1;
    }
    if (*signature_len < sig->length_signature) {
        fprintf(stderr, "buffer too small for Falcon-1024 signature\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_sign(sig,
                                 signature,
                                 signature_len,
                                 msg,
                                 msg_len,
                                 sk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

static int falcon1024_verify_cb(const uint8_t *msg, size_t msg_len,
                                const uint8_t *signature, size_t signature_len,
                                const uint8_t *pk, size_t pk_len)
{
    static OQS_SIG *sig = NULL;
    if (sig == NULL) {
        sig = OQS_SIG_new("Falcon-1024");
        if (sig == NULL) {
            fprintf(stderr, "OQS_SIG_new(Falcon-1024) failed\n");
            return -1;
        }
    }

    if (pk_len < sig->length_public_key) {
        fprintf(stderr, "buffer too small for Falcon-1024 pk\n");
        return -1;
    }

    OQS_STATUS st = OQS_SIG_verify(sig,
                                   msg,
                                   msg_len,
                                   signature,
                                   signature_len,
                                   pk);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

void bench_falcon1024_verify(int runs, size_t msg_len, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("Falcon-1024");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(Falcon-1024) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len  = sig->length_public_key;
    size_t sk_len  = sig->length_secret_key;
    size_t sig_len = sig->length_signature;
    OQS_SIG_free(sig);

    bench_verify_generic("Falcon-1024",
                         falcon1024_sign_for_verify_cb,
                         falcon1024_verify_cb,
                         falcon1024_keygen_for_verify,
                         msg_len,
                         pk_len,
                         sk_len,
                         sig_len,
                         runs,
                         csv_path);
}

/* =============================
 * Wrapper Ed25519 (OpenSSL)
 * ============================= */

static int ed25519_keygen_for_verify(uint8_t *pk, size_t pk_len,
                                     uint8_t *sk, size_t sk_len)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_ED25519, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id(NID_ED25519) failed\n");
        return -1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init(Ed25519) failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen(Ed25519) failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    size_t got_pk_len = pk_len;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &got_pk_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_get_raw_public_key(Ed25519) failed\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (got_pk_len > pk_len) {
        fprintf(stderr, "buffer too small for Ed25519 pk\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    size_t got_sk_len = sk_len;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &got_sk_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_get_raw_private_key(Ed25519) failed\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (got_sk_len > sk_len) {
        fprintf(stderr, "buffer too small for Ed25519 sk\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

static int ed25519_sign_for_verify_cb(const uint8_t *msg, size_t msg_len,
                                      uint8_t *signature, size_t *signature_len,
                                      const uint8_t *sk, size_t sk_len)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;

    pkey = EVP_PKEY_new_raw_private_key(NID_ED25519, NULL, sk, sk_len);
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new_raw_private_key(Ed25519) failed\n");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new() failed\n");
        goto cleanup;
    }

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit(Ed25519) failed\n");
        goto cleanup;
    }

    size_t tmp_sig_len = *signature_len;
    if (EVP_DigestSign(mdctx, signature, &tmp_sig_len, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_DigestSign(Ed25519) failed\n");
        goto cleanup;
    }

    *signature_len = tmp_sig_len;
    ret = 0;

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey)  EVP_PKEY_free(pkey);
    return ret;
}

static int ed25519_verify_cb(const uint8_t *msg, size_t msg_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *pk, size_t pk_len)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;

    pkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, pk, pk_len);
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new_raw_public_key(Ed25519) failed\n");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new() failed\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyInit(Ed25519) failed\n");
        goto cleanup;
    }

    int vret = EVP_DigestVerify(mdctx, signature, signature_len, msg, msg_len);
    if (vret != 1) {
        /* 0 = firma invalida, <0 = errore; in entrambi i casi per il bench ci fermiamo */
        fprintf(stderr, "EVP_DigestVerify(Ed25519) failed or invalid signature\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey)  EVP_PKEY_free(pkey);
    return ret;
}

void bench_ed25519_verify(int runs, size_t msg_len, const char *csv_path)
{
    /* Ricava pk_len, sk_len e sig_len (come nella sign) */

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_ED25519, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id(NID_ED25519) failed (length query)\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init(Ed25519) failed (length query)\n");
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen(Ed25519) failed (length query)\n");
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    size_t pk_len = 0;
    size_t sk_len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pk_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(pkey, NULL, &sk_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_get_raw_*_key(Ed25519) length query failed\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    /* Signature length */
    unsigned char dummy_msg[1] = {0};
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new() failed (sig length query)\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit(Ed25519) failed (sig length query)\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx, NULL, &sig_len, dummy_msg, sizeof(dummy_msg)) <= 0) {
        fprintf(stderr, "EVP_DigestSign(Ed25519) length query failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    bench_verify_generic("Ed25519",
                         ed25519_sign_for_verify_cb,
                         ed25519_verify_cb,
                         ed25519_keygen_for_verify,
                         msg_len,
                         pk_len,
                         sk_len,
                         sig_len,
                         runs,
                         csv_path);
}

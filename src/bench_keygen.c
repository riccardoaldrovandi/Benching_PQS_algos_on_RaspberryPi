// bench_keygen.c
#include "bench_keygen.h"
#include "benching.h"

#include <oqs/oqs.h>   // adatta il path se diverso
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
/* =============================
 * Benchmarking generico per keygen
 * ============================= */

 void bench_keygen_generic(const char *alg_name,
    keygen_func_t keygen,
    size_t pk_len,
    size_t sk_len,
    int runs,
    const char *csv_path)
{
uint8_t *pk = malloc(pk_len);
uint8_t *sk = malloc(sk_len);
if (!pk || !sk) {
fprintf(stderr, "malloc failed in bench_keygen_generic\n");
free(pk);
free(sk);
exit(EXIT_FAILURE);
}

FILE *csv = init_benching(csv_path);

// warmup: una keygen per “scaldare” cache, RNG, ecc.
if (keygen(pk, pk_len, sk, sk_len) != 0) {
fprintf(stderr, "keygen warmup failed for %s\n", alg_name);
destroy_benching(csv);
free(pk);
free(sk);
exit(EXIT_FAILURE);
}

// per avere qualcosa di interpretabile come "msg_len" nei CSV:
size_t key_bytes = pk_len + sk_len;

for (int i = 0; i < runs; i++) {
int event_set;
uint64_t start_time;

start_benching(&event_set, &start_time);

if (keygen(pk, pk_len, sk, sk_len) != 0) {
fprintf(stderr, "keygen failed for %s at run %d\n", alg_name, i);
destroy_benching(csv);
free(pk);
free(sk);
exit(EXIT_FAILURE);
}

stop_benching(csv, i, key_bytes, alg_name, event_set, start_time);
}

destroy_benching(csv);
free(pk);
free(sk);
}



/* =============================
 * Wrapper liboqs per algoritmi specifici
 * ============================= */

/* Per evitare di ricreare OQS_SIG ad ogni run, lo creiamo una sola volta
 * per wrapper, e lo teniamo static. In alternativa puoi creare/distruggere
 * ogni volta se preferisci semplicità.
 */

/* -------- ML-DSA-44 -------- */

static int mldsa44_keygen_cb(uint8_t *pk, size_t pk_len,
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

    int ret = OQS_SIG_keypair(sig, pk, sk);
    return ret;
}

void bench_mldsa44_keygen(int runs, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-44");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(ML-DSA-44) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len = sig->length_public_key;
    size_t sk_len = sig->length_secret_key;

    OQS_SIG_free(sig);  // qui lo usiamo solo per leggere le lunghezze

    bench_keygen_generic("ML-DSA-44",
                         mldsa44_keygen_cb,
                         pk_len,
                         sk_len,
                         runs,
                         csv_path);
}

/* -------- ML-DSA-65 -------- */

static int mldsa65_keygen_cb(uint8_t *pk, size_t pk_len,
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

void bench_mldsa65_keygen(int runs, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len = sig->length_public_key;
    size_t sk_len = sig->length_secret_key;
    OQS_SIG_free(sig);

    bench_keygen_generic("ML-DSA-65",
                         mldsa65_keygen_cb,
                         pk_len,
                         sk_len,
                         runs,
                         csv_path);
}

/* -------- Falcon-512 -------- */

static int falcon512_keygen_cb(uint8_t *pk, size_t pk_len,
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

void bench_falcon512_keygen(int runs, const char *csv_path)
{
    OQS_SIG *sig = OQS_SIG_new("Falcon-512");
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new(Falcon-512) failed (for length query)\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len = sig->length_public_key;
    size_t sk_len = sig->length_secret_key;
    OQS_SIG_free(sig);

    bench_keygen_generic("Falcon-512",
                         falcon512_keygen_cb,
                         pk_len,
                         sk_len,
                         runs,
                         csv_path);
}

/* -------- ML-DSA-87 -------- */

static int mldsa87_keygen_cb(uint8_t *pk, size_t pk_len,
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

void bench_mldsa87_keygen(int runs, const char *csv_path)
{
OQS_SIG *sig = OQS_SIG_new("ML-DSA-87");
if (sig == NULL) {
fprintf(stderr, "OQS_SIG_new(ML-DSA-87) failed (for length query)\n");
exit(EXIT_FAILURE);
}

size_t pk_len = sig->length_public_key;
size_t sk_len = sig->length_secret_key;
OQS_SIG_free(sig);

bench_keygen_generic("ML-DSA-87",
mldsa87_keygen_cb,
pk_len,
sk_len,
runs,
csv_path);
}

/* -------- Falcon-1024 -------- */

static int falcon1024_keygen_cb(uint8_t *pk, size_t pk_len,
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

void bench_falcon1024_keygen(int runs, const char *csv_path)
{
OQS_SIG *sig = OQS_SIG_new("Falcon-1024");
if (sig == NULL) {
fprintf(stderr, "OQS_SIG_new(Falcon-1024) failed (for length query)\n");
exit(EXIT_FAILURE);
}

size_t pk_len = sig->length_public_key;
size_t sk_len = sig->length_secret_key;
OQS_SIG_free(sig);

bench_keygen_generic("Falcon-1024",
falcon1024_keygen_cb,
pk_len,
sk_len,
runs,
csv_path);
}

/* -------- Ed25519 (OpenSSL) -------- */

static int ed25519_keygen_cb(uint8_t *pk, size_t pk_len,
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

// Estrai public key
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

// Estrai private key (seed raw)
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

void bench_ed25519_keygen(int runs, const char *csv_path)
{
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

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    bench_keygen_generic("Ed25519",
                         ed25519_keygen_cb,
                         pk_len,
                         sk_len,
                         runs,
                         csv_path);
}

// src/bench_kem_keygen.c
#include "bench_kem_keygen.h"
#include "bench_kem_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "benching.h"    // dichiara init_benching, start_benching, stop_benching, destroy_benching
#include "papi_util.h"   // se ti serve per event_set ecc.

// Stampa eventuali errori OpenSSL su stderr (utile per debug).
static void print_openssl_errors(const char *msg) {
    if (msg) {
        fprintf(stderr, "%s\n", msg);
    }
    ERR_print_errors_fp(stderr);
}

int bench_kem_keygen(const char *alg_name, int runs, const char *csv_path) {
    if (runs <= 0) {
        fprintf(stderr, "bench_kem_keygen: runs must be > 0\n");
        return -1;
    }

    kem_buffers_t ctx;
    if (kem_buffers_init(&ctx, alg_name) != 0) {
        return -1;
    }

    // dimensione chiavi (puoi cambiare criterio se ti serve solo pk o solo sk)
    size_t key_bytes = ctx.kem->length_public_key + ctx.kem->length_secret_key;

    FILE *csv = init_benching(csv_path);
    if (!csv) {
        fprintf(stderr, "bench_kem_keygen: init_benching failed\n");
        kem_buffers_free(&ctx);
        return -1;
    }

    for (int run = 0; run < runs; ++run) {
        int event_set;
        uint64_t start_time;

        start_benching(&event_set, &start_time);

        OQS_STATUS rc = OQS_KEM_keypair(ctx.kem, ctx.pk, ctx.sk);

        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "[%s] OQS_KEM_keypair failed on run %d\n", alg_name, run);
            destroy_benching(csv);
            kem_buffers_free(&ctx);
            return -1;
        }

        // run = indice della ripetizione, key_bytes = "dimensione" operazione
        stop_benching(csv, run, key_bytes, alg_name, event_set, start_time);
    }

    destroy_benching(csv);
    kem_buffers_free(&ctx);
    return 0;
}

int bench_x25519_ecdh(int runs, const char *csv_path) {
    if (runs <= 0) {
        fprintf(stderr, "bench_x25519_ecdh: runs must be > 0\n");
        return -1;
    }

    const char *alg_name = "X25519-ECDH";

    // Chiave "statica" (ricevente) generata una volta sola
    EVP_PKEY_CTX *ctx_static = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx_static) {
        print_openssl_errors("EVP_PKEY_CTX_new_id (static) failed");
        return -1;
    }
    if (EVP_PKEY_keygen_init(ctx_static) <= 0) {
        print_openssl_errors("EVP_PKEY_keygen_init (static) failed");
        EVP_PKEY_CTX_free(ctx_static);
        return -1;
    }
    EVP_PKEY *pkey_static = NULL;
    if (EVP_PKEY_keygen(ctx_static, &pkey_static) <= 0) {
        print_openssl_errors("EVP_PKEY_keygen (static) failed");
        EVP_PKEY_CTX_free(ctx_static);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx_static);

    FILE *csv = init_benching(csv_path);
    if (!csv) {
        fprintf(stderr, "bench_x25519_ecdh: init_benching failed\n");
        EVP_PKEY_free(pkey_static);
        return -1;
    }

    // shared secret X25519 = 32 byte
    size_t ss_len = 32;
    unsigned char ss[32];

    for (int run = 0; run < runs; ++run) {
        // chiave effimera "sender" per ogni run
        EVP_PKEY_CTX *ctx_eph = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        if (!ctx_eph) {
            print_openssl_errors("EVP_PKEY_CTX_new_id (eph) failed");
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }
        if (EVP_PKEY_keygen_init(ctx_eph) <= 0) {
            print_openssl_errors("EVP_PKEY_keygen_init (eph) failed");
            EVP_PKEY_CTX_free(ctx_eph);
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }
        EVP_PKEY *pkey_eph = NULL;

        int event_set;
        uint64_t start_time;

        start_benching(&event_set, &start_time);

        // keygen effimera + ECDH nella stessa finestra temporale
        if (EVP_PKEY_keygen(ctx_eph, &pkey_eph) <= 0) {
            print_openssl_errors("EVP_PKEY_keygen (eph) failed");
            EVP_PKEY_CTX_free(ctx_eph);
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }

        EVP_PKEY_CTX *ctx_derive = EVP_PKEY_CTX_new(pkey_eph, NULL);
        if (!ctx_derive) {
            print_openssl_errors("EVP_PKEY_CTX_new (derive) failed");
            EVP_PKEY_free(pkey_eph);
            EVP_PKEY_CTX_free(ctx_eph);
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }
        if (EVP_PKEY_derive_init(ctx_derive) <= 0) {
            print_openssl_errors("EVP_PKEY_derive_init failed");
            EVP_PKEY_CTX_free(ctx_derive);
            EVP_PKEY_free(pkey_eph);
            EVP_PKEY_CTX_free(ctx_eph);
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }
        if (EVP_PKEY_derive_set_peer(ctx_derive, pkey_static) <= 0) {
            print_openssl_errors("EVP_PKEY_derive_set_peer failed");
            EVP_PKEY_CTX_free(ctx_derive);
            EVP_PKEY_free(pkey_eph);
            EVP_PKEY_CTX_free(ctx_eph);
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }

        size_t out_len = ss_len;
        if (EVP_PKEY_derive(ctx_derive, ss, &out_len) <= 0 || out_len != ss_len) {
            print_openssl_errors("EVP_PKEY_derive failed");
            EVP_PKEY_CTX_free(ctx_derive);
            EVP_PKEY_free(pkey_eph);
            EVP_PKEY_CTX_free(ctx_eph);
            destroy_benching(csv);
            EVP_PKEY_free(pkey_static);
            return -1;
        }

        stop_benching(csv, run, ss_len, alg_name, event_set, start_time);

        EVP_PKEY_CTX_free(ctx_derive);
        EVP_PKEY_free(pkey_eph);
        EVP_PKEY_CTX_free(ctx_eph);
    }

    destroy_benching(csv);
    EVP_PKEY_free(pkey_static);

    return 0;
}
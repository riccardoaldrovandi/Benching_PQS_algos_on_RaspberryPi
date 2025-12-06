// src/bench_kem_common.c
#include "bench_kem_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kem_buffers_init(kem_buffers_t *ctx, const char *alg_name) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->kem = OQS_KEM_new(alg_name);
    if (ctx->kem == NULL) {
        fprintf(stderr, "OQS_KEM_new(%s) failed\n", alg_name);
        return -1;
    }

    ctx->pk = malloc(ctx->kem->length_public_key);
    ctx->sk = malloc(ctx->kem->length_secret_key);
    ctx->ct = malloc(ctx->kem->length_ciphertext);
    ctx->ss = malloc(ctx->kem->length_shared_secret);

    if (!ctx->pk || !ctx->sk || !ctx->ct || !ctx->ss) {
        fprintf(stderr, "malloc failed in kem_buffers_init\n");
        kem_buffers_free(ctx);
        return -1;
    }

    return 0;
}

void kem_buffers_free(kem_buffers_t *ctx) {
    if (!ctx) return;

    if (ctx->pk) {
        memset(ctx->pk, 0, ctx->kem ? ctx->kem->length_public_key : 0);
        free(ctx->pk);
    }
    if (ctx->sk) {
        memset(ctx->sk, 0, ctx->kem ? ctx->kem->length_secret_key : 0);
        free(ctx->sk);
    }
    if (ctx->ct) {
        memset(ctx->ct, 0, ctx->kem ? ctx->kem->length_ciphertext : 0);
        free(ctx->ct);
    }
    if (ctx->ss) {
        memset(ctx->ss, 0, ctx->kem ? ctx->kem->length_shared_secret : 0);
        free(ctx->ss);
    }

    if (ctx->kem) {
        OQS_KEM_free(ctx->kem);
    }

    memset(ctx, 0, sizeof(*ctx));
}

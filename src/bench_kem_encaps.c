// src/bench_kem_encaps.c
#include "bench_kem_encaps.h"
#include "bench_kem_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <oqs/oqs.h>

#include "benching.h"
#include "papi_util.h"

int bench_kem_encaps(const char *alg_name, int runs, const char *csv_path) {
    if (runs <= 0) {
        fprintf(stderr, "bench_kem_encaps: runs must be > 0\n");
        return -1;
    }

    kem_buffers_t ctx;
    if (kem_buffers_init(&ctx, alg_name) != 0) {
        return -1;
    }

    // keypair una volta sola, così nel loop misuri solo encaps
    if (OQS_KEM_keypair(ctx.kem, ctx.pk, ctx.sk) != OQS_SUCCESS) {
        fprintf(stderr, "[%s] OQS_KEM_keypair failed in bench_kem_encaps\n",
                alg_name);
        kem_buffers_free(&ctx);
        return -1;
    }

    // dimensione operazione = ciphertext + shared secret
    size_t op_bytes = ctx.kem->length_ciphertext + ctx.kem->length_shared_secret;

    FILE *csv = init_benching(csv_path);
    if (!csv) {
        fprintf(stderr, "bench_kem_encaps: init_benching failed\n");
        kem_buffers_free(&ctx);
        return -1;
    }

    for (int run = 0; run < runs; ++run) {
        int event_set;
        uint64_t start_time;

        start_benching(&event_set, &start_time);

        OQS_STATUS rc = OQS_KEM_encaps(ctx.kem, ctx.ct, ctx.ss, ctx.pk);
        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "[%s] OQS_KEM_encaps failed on run %d\n",
                    alg_name, run);
            destroy_benching(csv);
            kem_buffers_free(&ctx);
            return -1;
        }

        stop_benching(csv, run, op_bytes, alg_name, event_set, start_time);
    }

    destroy_benching(csv);
    kem_buffers_free(&ctx);
    return 0;
}

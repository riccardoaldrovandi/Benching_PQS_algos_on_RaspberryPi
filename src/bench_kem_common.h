// src/bench_kem_common.h
#ifndef BENCH_KEM_COMMON_H
#define BENCH_KEM_COMMON_H

#include <oqs/oqs.h>
#include <stdint.h>

typedef struct {
    OQS_KEM *kem;
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *ct;
    uint8_t *ss;
} kem_buffers_t;

/**
 * Inizializza il KEM e alloca tutti i buffer necessari.
 * Ritorna 0 su successo, -1 su errore.
 */
int kem_buffers_init(kem_buffers_t *ctx, const char *alg_name);

/**
 * Libera tutti i buffer e il KEM.
 */
void kem_buffers_free(kem_buffers_t *ctx);

#endif // BENCH_KEM_COMMON_H

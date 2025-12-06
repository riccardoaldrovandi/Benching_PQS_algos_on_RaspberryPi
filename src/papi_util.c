// papi_util.c
#include "papi_util.h"
#include <stdio.h>
#include <stdlib.h>

static int papi_initialized = 0;

static void handle_papi_error(int retval, const char *msg) {
    if (retval != PAPI_OK) {
        fprintf(stderr, "PAPI error in %s: %s\n", msg, PAPI_strerror(retval));
        exit(EXIT_FAILURE);
    }
}

int init_papi(void) {
    int retval;

    if (!papi_initialized) {
        retval = PAPI_library_init(PAPI_VER_CURRENT);
        if (retval != PAPI_VER_CURRENT) {
            fprintf(stderr, "PAPI_library_init failed: %d\n", retval);
            exit(EXIT_FAILURE);
        }
        papi_initialized = 1;
    }

    int event_set = PAPI_NULL;

    retval = PAPI_create_eventset(&event_set);
    handle_papi_error(retval, "PAPI_create_eventset");

    // Aggiungi gli eventi che ti interessano
    retval = PAPI_add_event(event_set, PAPI_TOT_CYC);
    handle_papi_error(retval, "PAPI_add_event(PAPI_TOT_CYC)");

    retval = PAPI_add_event(event_set, PAPI_TOT_INS);
    handle_papi_error(retval, "PAPI_add_event(PAPI_TOT_INS)");

    retval = PAPI_add_event(event_set, PAPI_L1_DCM);  // L1 data cache miss
    handle_papi_error(retval, "PAPI_add_event(PAPI_L1_DCM)");

    // Avvia l'EventSet
    retval = PAPI_start(event_set);
    handle_papi_error(retval, "PAPI_start");

    return event_set;
}

void papi_read(int event_set,
               long long *total_cycles,
               long long *total_instructions,
               long long *l1_cache_miss)
{
    if (!total_cycles || !total_instructions || !l1_cache_miss) {
        fprintf(stderr, "papi_read: NULL pointer argument\n");
        exit(EXIT_FAILURE);
    }

    long long values[3];
    int retval = PAPI_read(event_set, values);
    handle_papi_error(retval, "PAPI_read");

    *total_cycles       = values[0];
    *total_instructions = values[1];
    *l1_cache_miss      = values[2];
}

void stop_papi(int event_set) {
    long long values[3];
    int retval;

    retval = PAPI_stop(event_set, values);
    handle_papi_error(retval, "PAPI_stop");

    retval = PAPI_cleanup_eventset(event_set);
    handle_papi_error(retval, "PAPI_cleanup_eventset");

    retval = PAPI_destroy_eventset(&event_set);
    handle_papi_error(retval, "PAPI_destroy_eventset");
}

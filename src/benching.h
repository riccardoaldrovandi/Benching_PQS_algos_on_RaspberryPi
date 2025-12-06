// benching.h
#ifndef BENCHING_H
#define BENCHING_H

#include "papi_util.h"
#include "profiling.h"
#include <stdint.h>
#include <stdio.h>

FILE *init_benching(const char *csv_path);

void start_benching(int *event_set, uint64_t *start_time);

void stop_benching(FILE *csv,
                   int run_index,
                   size_t msg_len,
                   const char *alg_name,
                   int event_set,
                   uint64_t start_time);

void destroy_benching(FILE *csv);

#endif


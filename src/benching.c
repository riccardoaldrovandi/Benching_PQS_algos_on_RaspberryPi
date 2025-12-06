// benching.c
#include "benching.h"
#include <stdlib.h>

FILE *init_benching(const char *csv_path) {
    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fprintf(csv,
            "run_index,time_ns,time_us,msg_len,alg,"
            "total_cycles,total_instructions,l1_cache_miss,ram_usage\n");
    fflush(csv);
    return csv;
}

void start_benching(int *event_set, uint64_t *start_time) {
    *event_set  = init_papi();
    *start_time = now_ns();
}

void stop_benching(FILE *csv,
                   int run_index,
                   size_t msg_len,
                   const char *alg_name,
                   int event_set,
                   uint64_t start_time)
{
    uint64_t end_time = now_ns();

    long long total_cycles;
    long long total_instructions;
    long long l1_cache_miss;
    long      ram_usage;

    papi_read(event_set,
              &total_cycles,
              &total_instructions,
              &l1_cache_miss);

    uint64_t dt_ns = end_time - start_time;
    double   dt_us = dt_ns / 1000.0;

    get_memory_usage(&ram_usage);

    fprintf(csv, "%d,%llu,%.3f,%zu,%s,%lld,%lld,%lld,%ld\n",
            run_index,
            (unsigned long long)dt_ns,
            dt_us,
            msg_len,
            alg_name,
            total_cycles,
            total_instructions,
            l1_cache_miss,
            ram_usage);
    fflush(csv);

    stop_papi(event_set);
}

void destroy_benching(FILE *csv) {
    fclose(csv);
}

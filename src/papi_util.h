#ifndef PAPI_UTIL_H
#define PAPI_UTIL_H

#include <papi.h>

int init_papi();
void papi_read(int event_set,
               long long *total_cycles,
               long long *total_instructions,
               long long *l1_cache_miss);
void stop_papi(int event_set);

#endif

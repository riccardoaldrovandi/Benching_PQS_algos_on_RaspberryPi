#ifndef PROFILING_H
#define PROFILING_H

#include <stdint.h>
#include <stdio.h>

// Funzione per ottenere i cicli di clock
//uint64_t get_cycles(void);

// Funzione per leggere i contatori PMU (istruzioni, cache miss/hit)
//uint64_t read_pmc(int counter);

// Funzione per ottenere l'uso della memoria
void get_memory_usage(long *ram_usage);

// Funzione per ottenere il tempo attuale in nanosecondi
uint64_t now_ns(void);

#endif

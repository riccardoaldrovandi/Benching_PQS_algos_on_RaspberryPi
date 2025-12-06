#include "profiling.h"
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <stdint.h>

// Funzione per ottenere i cicli di clock

/*
uint64_t get_cycles(void) {
    uint32_t hi, lo;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); 
    return ((uint64_t)lo) | ((uint64_t)hi << 32);
}

// Funzione per leggere i contatori PMU (istruzioni, cache miss/hit)
uint64_t read_pmc(int counter) {
    uint64_t value;
    __asm__ volatile(
        "rdpmc" 
        : "=A"(value) 
        : "c"(counter)
    );
    return value;
}
*/
// Funzione per ottenere l'uso della memoria
void get_memory_usage(long *ram_usage) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage failed");
        exit(EXIT_FAILURE);
    }
    *ram_usage = usage.ru_maxrss;  // Uso della memoria in KB
}

// Funzione per ottenere il tempo attuale in nanosecondi
uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

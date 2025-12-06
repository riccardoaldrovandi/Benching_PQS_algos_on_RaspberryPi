// src/util_csv.c
#include "util_csv.h"

#include <stdarg.h>
#include <stdlib.h>

FILE *csv_open(const char *path, const char *header) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    if (header) {
        fprintf(f, "%s\n", header);
        fflush(f);
    }
    return f;
}

void csv_printf(FILE *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
}

void csv_close(FILE *f) {
    if (!f) return;
    fclose(f);
}

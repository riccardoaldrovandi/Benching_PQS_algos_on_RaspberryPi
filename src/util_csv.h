// src/util_csv.h
#ifndef UTIL_CSV_H
#define UTIL_CSV_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Apre un file CSV in scrittura.
 * Se header non è NULL, viene scritto come prima riga (terminata da '\n').
 */
FILE *csv_open(const char *path, const char *header);

/**
 * Scrive una riga CSV generica.
 * Esempio d'uso:
 *   csv_printf(csv, "%d,%llu,%zu\n", run_idx, (unsigned long long)time_ns, msg_len);
 */
void csv_printf(FILE *f, const char *fmt, ...);

/**
 * Chiude il CSV (wrapper per fclose).
 */
void csv_close(FILE *f);

#endif // UTIL_CSV_H


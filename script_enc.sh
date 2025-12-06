#!/bin/bash

echo "Running Encapsulation Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/encaps"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi di cifratura (aggiungi i tuoi algoritmi di cifratura)
enc_algorithms=("aes256gcm" "chacha20poly1305" "ascon128")

# Lunghezze dei messaggi (msg_len) per ogni algoritmo
msg_lengths=(64 128 512 4096)

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del messaggio
for enc in "${enc_algorithms[@]}"; do
  for msg_len in "${msg_lengths[@]}"; do
    echo "Running benchmark for $enc with msg_len=$msg_len..."
    ./pqc_bench enc $enc $msg_len 100 "$RESULT_DIR/${enc}_${msg_len}_enc_benchmark.csv"
  done
done

echo "Encapsulation Benchmarking Completed!"

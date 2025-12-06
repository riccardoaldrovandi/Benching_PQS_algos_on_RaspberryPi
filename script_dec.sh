#!/bin/bash

echo "Running Decapsulation Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/decaps"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi di decifrazione (aggiungi i tuoi algoritmi di decifrazione)
dec_algorithms=("aes256gcm" "chacha20poly1305" "ascon128")

# Lunghezze dei messaggi (msg_len) per ogni algoritmo
msg_lengths=(64 128 512 4096)

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del messaggio
for dec in "${dec_algorithms[@]}"; do
  for msg_len in "${msg_lengths[@]}"; do
    echo "Running benchmark for $dec with msg_len=$msg_len..."
    ./pqc_bench dec $dec $msg_len 100 "$RESULT_DIR/${dec}_${msg_len}_dec_benchmark.csv"
  done
done

echo "Decapsulation Benchmarking Completed!"

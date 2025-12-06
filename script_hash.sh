#!/bin/bash

echo "Running Hash Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/hash"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi di hash (aggiungi i tuoi algoritmi)
hash_algorithms=("sha256" "sha3-256" "ascon-hash256")

# Lunghezze dei messaggi (msg_len) per ogni algoritmo
msg_lengths=(64 128 512 4096)

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del messaggio
for hash in "${hash_algorithms[@]}"; do
  for msg_len in "${msg_lengths[@]}"; do
    echo "Running benchmark for $hash with msg_len=$msg_len..."
    ./pqc_bench hash $hash $msg_len 100 "$RESULT_DIR/${hash}_${msg_len}_benchmark.csv"
  done
done

echo "Hash Benchmarking Completed!"

#!/bin/bash

echo "Running Sign Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/sign"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi di firma (aggiungi i tuoi algoritmi di firma)
sign_algorithms=("mldsa44" "mldsa65" "mldsa87" "falcon512" "falcon1024" "ed25519")

# Lunghezze dei messaggi (msg_len) per ogni algoritmo
msg_lengths=(64 128 512 4096)

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del messaggio
for sign in "${sign_algorithms[@]}"; do
  for msg_len in "${msg_lengths[@]}"; do
    echo "Running benchmark for $sign with msg_len=$msg_len..."
    ./pqc_bench sign $sign $msg_len 100 "$RESULT_DIR/${sign}_${msg_len}_sign_benchmark.csv"
  done
done

echo "Sign Benchmarking Completed!"

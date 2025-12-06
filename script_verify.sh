#!/bin/bash

echo "Running Verify Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/verify"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi di verifica (aggiungi i tuoi algoritmi di firma)
verify_algorithms=("mldsa44" "mldsa65" "mldsa87" "falcon512" "falcon1024" "ed25519")

# Lunghezze dei messaggi (msg_len) per ogni algoritmo
msg_lengths=(64 128 512 4096)

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del messaggio
for verify in "${verify_algorithms[@]}"; do
  for msg_len in "${msg_lengths[@]}"; do
    echo "Running benchmark for $verify with msg_len=$msg_len..."
    ./pqc_bench verify $verify $msg_len 100 "$RESULT_DIR/${verify}_${msg_len}_verify_benchmark.csv"
  done
done

echo "Verify Benchmarking Completed!"

#!/bin/bash

echo "Running KDF Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/kdf"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi KDF
kdf_algorithms=("hkdf_sha256" "hkdf_sha384" "hkdf_sha512" "hmac_sha256" "cmac_aes256" "blake2b" "shake128" "shake256")

# Lunghezze dei secret per ogni algoritmo
secret_lengths=(64 128 512 4096)

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del secret
for kdf in "${kdf_algorithms[@]}"; do
  for secret_len in "${secret_lengths[@]}"; do
    echo "Running benchmark for $kdf with secret_len=$secret_len..."
    ./pqc_bench kdf $kdf $secret_len 100 "$RESULT_DIR/${kdf}_${secret_len}_kdf_benchmark.csv"
  done
done

echo "KDF Benchmarking Completed!"

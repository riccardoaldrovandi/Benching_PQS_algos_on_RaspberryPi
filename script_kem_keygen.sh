#!/bin/bash

echo "Running KEM Keygen Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/kem/keygen"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi KEM (kemkeygen)
kemkeygen_algorithms=("mlkem512" "mlkem768" "mlkem1024" "hqc128" "hqc192" "hqc256" "bike_l1" "bike_l3" "cm348864" "cm6688128" "ntru_hps2048509" "ntru_hps4096821" "ntru_hrss701" "sntrup761" "frodokem640aes" "frodokem976aes" "x25519")

# Esegui benchmark per ogni algoritmo KEM di keygen
for alg in "${kemkeygen_algorithms[@]}"; do
    echo "Running KEM Keygen for $alg"
    ./pqc_bench kemkeygen $alg 100 "$RESULT_DIR/$alg.csv"
done

echo "KEM Keygen Benchmarking complete!"

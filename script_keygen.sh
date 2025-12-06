#!/bin/bash

echo "Running Keygen Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/keygen"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi Keygen per firma (escludendo KEM)
keygen_algorithms=("mldsa44" "mldsa65" "mldsa87" "falcon512" "falcon1024" "ed25519")

# Esegui benchmark per ogni algoritmo di keygen
for alg in "${keygen_algorithms[@]}"; do
    echo "Running Keygen for $alg"
    ./pqc_bench keygen $alg 100 "$RESULT_DIR/$alg.csv"
done

echo "Keygen Benchmarking complete!"

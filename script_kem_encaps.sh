#!/bin/bash

echo "Running KEM Encapsulation Benchmarking..."

# Percorso della cartella dei risultati
RESULT_DIR="result/kem/encaps"

# Crea la cartella dei risultati se non esiste
mkdir -p $RESULT_DIR

# Algoritmi KEM Encapsulation (tutti gli algoritmi KEM)
kem_encaps_algorithms=("mlkem512" "mlkem768" "mlkem1024" "hqc128" "hqc192" "hqc256" "bike_l1" "bike_l3" "cm348864" "cm6688128" "ntru_hps2048509" "ntru_hps4096821" "ntru_hrss701" "sntrup761" "frodokem640aes" "frodokem976aes" "x25519")

# Esegui il benchmark per ogni algoritmo e per ogni lunghezza del messaggio
for kem in "${kem_encaps_algorithms[@]}"; do
  echo "Running benchmark for $kem"
  ./pqc_bench kemencaps $kem 100 "$RESULT_DIR/${kem}_kemencaps_benchmark.csv"
done

echo "KEM Encapsulation Benchmarking Completed!"

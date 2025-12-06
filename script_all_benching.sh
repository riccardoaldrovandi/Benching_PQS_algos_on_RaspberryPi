#!/bin/bash

rm result/*

echo "Starting all benchmarks..."

# Lancia tutti gli script
sudo ./script_hash.sh && sudo ./script_keygen.sh && sudo ./script_sign.sh && sudo ./script_verify.sh && sudo ./script_enc.sh && sudo ./script_dec.sh && sudo ./script_kem_keygen.sh && sudo ./script_kem_encaps.sh && sudo ./script_kem_decaps.sh && sudo ./script_kdf.sh 

echo "All benchmarks completed!"

sudo python3 process_results.py
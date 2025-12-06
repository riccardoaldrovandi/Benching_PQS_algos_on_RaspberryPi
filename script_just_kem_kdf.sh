#!/bin/bash

rm -r result/kem/*
rm -r result/kdf/*

echo "Starting all benchmarks..."

# Lancia tutti gli script
sudo ./script_kem_keygen.sh && sudo ./script_kem_encaps.sh && sudo ./script_kem_decaps.sh && sudo ./script_kdf.sh 

echo "All benchmarks completed!"

sudo python3 process_results.py

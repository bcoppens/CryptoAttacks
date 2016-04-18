#!/bin/bash

set -u
set -e

echo "Building object file..."
gcc -g -c -o time_own_execution.o time_own_execution.c

echo "Linking binaries..."
gcc -o ecdsa_time_vuln time_own_execution.o vulnerable_openssl/libcrypto.a -ldl
# gcc -o ecdsa_time_safe time_own_execution.o -Lfixed_openssl -lcrypto -ldl

echo "Timing..."
taskset --cpu-list 0 ./ecdsa_time_vuln > timings.csv


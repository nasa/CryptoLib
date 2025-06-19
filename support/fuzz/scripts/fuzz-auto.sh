#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd $SCRIPT_DIR
./build-fuzz.sh
cd ..
python3 generate_corpus.py
cd ./scripts
./run-fuzz-multithreaded.sh
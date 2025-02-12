#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_rhel.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

rm $BASE_DIR/CMakeCache.txt
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
cmake $BASE_DIR -DCODECOV=1 -DDEBUG=1 -DMC_INTERNAL=1 -DTEST=1 -DSA_FILE=1 && make && make test


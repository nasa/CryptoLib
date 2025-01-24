#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_wolf.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

rm $BASE_DIR/CMakeCache.txt

cmake $BASE_DIR -DCODECOV=1 -DDEBUG=1 -DCRYPTO_LIBGCRYPT=0 -DCRYPTO_WOLFSSL=1 -DTEST=1 -DSA_FILE=1 && make && make test

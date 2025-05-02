#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_minimal.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

rm $BASE_DIR/CMakeCache.txt

cmake $BASE_DIR -DMC_DISABLED=1 -DCRYPTO_LIBGCRYPT=1 -DKEY_INTERNAL=1 -DSA_INTERNAL=1 && make && make test

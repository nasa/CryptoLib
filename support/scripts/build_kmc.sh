#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_kmc.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

rm $BASE_DIR/CMakeCache.txt
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
cmake $BASE_DIR -DCODECOV=1 -DDEBUG=1 -DCRYPTO_KMC=1 -DKEY_KMC=1 -DMC_DISABLED=1 -DSA_MARIADB=1 -DTEST=1 -DKMC_CFFI_EXCLUDE=1 -DSA_FILE=1 -DKMC_MDB_DB=1 && make && make test

#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_kmc.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

cmake $BASE_DIR -DCODECOV=1 -DDEBUG=1 -DCRYPTO_KMC=1 -DKEY_KMC=1 -DMC_DISABLED=1 -DSA_MARIADB=1 -DTEST=1 -DTEST_ENC=1 -DKMC_CFFI_EXCLUDE=1 -DSA_FILE=1 && make && make test

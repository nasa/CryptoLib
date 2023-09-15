#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_wolf.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

cmake $BASE_DIR -DCODECOV=1 -DDEBUG=1 -DCRYPTO_LIBGCRYPT=0 -DCRYPTO_WOLFSSL=1 -DSUPPORT=1 -DTEST=1 -DTEST_ENC=1 && make && make test

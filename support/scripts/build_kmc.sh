#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_internal.sh
#

cmake ../.. -DCODECOV=1 -DDEBUG=1 -DCRYPTO_KMC=1 -DKEY_KMC=1 -DSA_MARIADB=1 -DTEST=1 -DTEST_ENC=1 && make && make test

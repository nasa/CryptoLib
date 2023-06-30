#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_internal.sh
#

SCRIPT_DIR=$(cd `dirname $0` && pwd)
BASE_DIR=$(cd `dirname $SCRIPT_DIR`/.. && pwd)

cmake $BASE_DIR -DCODECOV=1 -DDEBUG=1 -DSUPPORT=1 -DTEST=1 -DTEST_ENC=1 && make && make test

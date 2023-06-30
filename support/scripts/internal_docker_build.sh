#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./internal_docker_build.sh
#

SCRIPT_DIR=$(cd `dirname $0` && pwd)
BASE_DIR=$(cd `dirname $SCRIPT_DIR`/.. && pwd)
DFLAGS="docker run --rm -it"


# Prepare build directory
mkdir $BASE_DIR/build > /dev/null 2>&1
rm -r $BASE_DIR/build/default/* > /dev/null 2>&1
mkdir $BASE_DIR/build/default > /dev/null 2>&1

#$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build cryptolib /bin/bash

echo "Default build and test..."
$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/default ivvitc/cryptolib bash -c \
    "cmake ../.. -DCODECOV=1 -DDEBUG=1 -DSUPPORT=1 -DTEST=1 -DTEST_ENC=1 && make && make test"
echo ""

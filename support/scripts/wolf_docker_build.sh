#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./internal_docker_build.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

# Prepare build directory
mkdir $BASE_DIR/build > /dev/null 2>&1
rm -r $BASE_DIR/build/internal/* > /dev/null 2>&1
mkdir $BASE_DIR/build/internal > /dev/null 2>&1

#$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/internal ivvitc/cryptolib /bin/bash

echo "Wolf build and test..."
$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/internal ivvitc/cryptolib bash -c \
    "../../support/scripts/build_wolf.sh"
echo ""

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

#$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/internal $DBOX /bin/bash

echo "Internal build and test..."
$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/internal $DBOX bash -c \
    "../../support/scripts/build_internal.sh"
echo ""

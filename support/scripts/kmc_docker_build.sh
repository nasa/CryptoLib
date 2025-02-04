#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./kmc_docker_build.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

# Prepare build directory
mkdir $BASE_DIR/build > /dev/null 2>&1
rm -r $BASE_DIR/build/kmc/* > /dev/null 2>&1
mkdir $BASE_DIR/build/kmc > /dev/null 2>&1

#$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/kmc $DBOX /bin/bash

echo "KMC build and test..."
# Note that the `KMC_MDB_DB` flag is not in use as docker compose will need configured to enable these tests
$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/build/kmc $DBOX bash -c \
    "../../support/scripts/build_kmc.sh"
echo ""

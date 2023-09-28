#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./internal_docker_build.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

echo "Start docker container to debug in..."
$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR ivvitc/cryptolib bash
echo ""

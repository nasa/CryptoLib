#!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will build in current directory
#
#  ./build_internal.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

cmake $BASE_DIR && make && make test

#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./build_docs.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

cd $BASE_DIR/docs/wiki > /dev/null 2>&1
echo "Creating Documentation Wiki Pages"
sphinx-build -b html . _build
echo ""


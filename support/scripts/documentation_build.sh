#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./documentation_build.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

echo "Building Sphinx Documentation..."
$DFLAGS -v $BASE_DIR:$BASE_DIR -w $BASE_DIR/docs/wiki $DBOX bash -c \
    "../../support/scripts/build_docs.sh"
echo ""

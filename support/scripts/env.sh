#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  source ./env.sh
#

export SCRIPT_DIR=$(cd `dirname $0` && pwd)
export BASE_DIR=$(cd `dirname $SCRIPT_DIR`/.. && pwd)
export DFLAGS="docker run --rm -it"

#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  source ./env.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BASE_DIR=$(cd `dirname $SCRIPT_DIR`/.. && pwd)
export DFLAGS="docker run --rm -it"

DBOX="ivvitc/cryptolib:20240814"

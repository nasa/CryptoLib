#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  source ./env.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BASE_DIR=$(cd `dirname $SCRIPT_DIR`/.. && pwd)

DFLAGS="docker run --rm -it -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro -u $(id -u $(stat -c '%U' $SCRIPT_DIR/env.sh)):$(getent group $(stat -c '%G' $SCRIPT_DIR/env.sh) | cut -d: -f3)"

DBOX="ivvitc/cryptolib:20250205"

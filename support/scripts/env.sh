#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  source ./env.sh
#

# Helper Functions for conditional stat -c calls
get_file_user() {
    if stat --version >/dev/null 2>&1; then
        stat -c '%U' "$1"
    else
        stat -f '%Su' "$1"
    fi
}

get_file_group() {
    if stat --version >/dev/null 2>&1; then
        stat -c '%G' "$1"
    else
        stat -f '%Sg' "$1"
    fi
}

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BASE_DIR=$(cd "$(dirname "$SCRIPT_DIR")"/.. && pwd)

file_user=$(get_file_user "$SCRIPT_DIR/env.sh")
file_group=$(get_file_group "$SCRIPT_DIR/env.sh")

# Conditional mount for passwd/group files (Linux only)
if [[ "$(uname)" == "Linux" ]]; then
    PASSWD_MOUNTS="-v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro"
else
    PASSWD_MOUNTS=""
fi

DFLAGS="docker run --rm -it \
    $PASSWD_MOUNTS \
    -u $(id -u "$file_user"):$(getent group "$file_group" | cut -d: -f3)"

DBOX="ivvitc/cryptolib:20250108"

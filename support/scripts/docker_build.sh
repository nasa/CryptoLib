#!/bin/bash -i
#
# Convenience script for CryptoLib development
#
#  ./docker_build.sh
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/env.sh

$SCRIPT_DIR/internal_docker_build.sh
$SCRIPT_DIR/kmc_docker_build.sh
$SCRIPT_DIR/wolf_docker_build.sh

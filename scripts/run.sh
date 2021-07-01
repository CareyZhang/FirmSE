#!/bin/bash

set -e
set -u

if [ -e ./firmse.config ]; then
    source ./firmse.config
elif [ -e ../firmse.config ]; then
    source ../firmse.config
else
    echo "Error: Could not find 'firmse.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: run.sh <image ID> [<architecture>]"
    exit 1
fi

IID=${1}
ARCH=${2}

${SCRIPT_DIR}/run.${ARCH}.sh ${IID}

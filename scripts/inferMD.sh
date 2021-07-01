#!/bin/bash
if [ -e ./firmse.config ]; then
    source ./firmse.config
elif [ -e ../firmse.config ]; then
    source ../firmse.config
else
    echo "Error: Could not find 'firmse.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: makeImage.sh <image ID> [<architecture>]"
    exit 1
fi

if check_root; then
    echo "Error: This script requires root privileges!"
    exit 1
fi

IID=${1}
WORK_DIR=`get_scratch ${IID}`
IMAGE_DIR="${WORK_DIR}/image"
MD_BINARY_DIR="${WORK_DIR}/md_binary"
MD_CONFIG_DIR="${WORK_DIR}/md_config"
MD_BINARY_LOG_DIR="${WORK_DIR}/md_binary/log"

for md in `cat ${WORK_DIR}/md_list`
do
    touch ${MD_CONFIG_DIR}/${md}.config
    for binary in `cat ${MD_BINARY_LOG_DIR}/$md`
    do
        timeout --preserve-status --signal SIGINT ${SYMBOLIC_EXEC_TIMEOUT} ${SCRIPT_DIR}/search.py ${MD_BINARY_DIR}/$binary $md ${MD_CONFIG_DIR} 2>&1 > /dev/null
    done
done
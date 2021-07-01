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
MD_BINARY_LOG_DIR="${WORK_DIR}/md_binary/log"

if [ ! -d $MD_BINARY_LOG_DIR ]; then
    mkdir -p $MD_BINARY_LOG_DIR
fi

candidate=()

for f in `find "${WORK_DIR}/image"`
do
    filetype=`file $f`
    if [ $filetype == *"ELF"* ];then
        if `BIN_filter $f`;then
            candidate+=("$f")
        fi
    fi
done

for f in "${candidate[@]}"
do
    fname = `basename $f`
    if `bin_filter $fname`; then
        devs=`ack "\/dev\/[A-Za-z0-9_]*" $f | strings | grep -oe "\/dev\/[A-Za-z0-9_]*" | cut -d '/' -f3 | tr ' ' '\n' | sort | uniq`
        for md in `cat ${WORK_DIR}/md_list`
        do
            if `printf '%s\n' "${devs[@]}" | grep "$md\$"`; then
                echo $fname >> ${MD_BINARY_LOG_DIR}/$md
                cat ${MD_BINARY_LOG_DIR}/$md | sort | uniq > ${MD_BINARY_LOG_DIR}/$md
                if [ -e ${MD_BINARY_DIR}/$fname ]; then
                    cp $f ${MD_BINARY_DIR}
                fi
            fi
        done
    fi
done
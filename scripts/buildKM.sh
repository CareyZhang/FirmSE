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
ARCH=`get_arch $IID`
KERNEL_VERSION=`get_kernel_version $IID`

cd ${KERNEL_DIR}/${ARCH}/${KERNEL_VERSION}/kernel_module/script
./build_all_module
for md in `cat ${WORK_DIR}/md_list`
do
    ./compile_md $md
done
cd -

if [ -d ${WORK_DIR}/file_ko ]; then
    rm -r ${WORK_DIR}/file_ko
fi

if [ -d ${WORK_DIR}/md_ko ]; then
    rm -r ${WORK_DIR}/md_ko
fi

cp -r ${KERNEL_DIR}/${ARCH}/${KERNEL_VERSION}/kernel_module/file_ko ${WORK_DIR}
cp -r ${KERNEL_DIR}/${ARCH}/${KERNEL_VERSION}/kernel_module/md_ko ${WORK_DIR}
rm ${KERNEL_DIR}/${ARCH}/${KERNEL_VERSION}/kernel_module/file_ko/*
rm ${KERNEL_DIR}/${ARCH}/${KERNEL_VERSION}/kernel_module/md_ko/*
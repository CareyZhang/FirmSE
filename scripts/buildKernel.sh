#!/bin/bash
set -x
if [ -e ./firmse.config ]; then
    source ./firmse.config
elif [ -e ../firmse.config ]; then
    source ../firmse.config
else
    echo "Error: Could not find 'firmse.config'!"
    exit 1
fi

IID=${1}

SCRATCH_IID=`get_scratch ${IID}`
ARCH=`${SCRIPT_DIR}/getArch.py ./images/${IID}.tar.gz ${PSQL_IP}`

KERNEL_VERSION=`${SCRIPT_DIR}/util.py select kernel_version ${IID} | grep -oe "[0-9.]*[0-9]*"`

case ${ARCH} in
    armel)
        KERNEL_NAME="zImage"
        ;;
    mipseb)
        KERNEL_NAME="vmlinux"
        ;;
    mipsel)
        KERNEL_NAME="vmlinux"
        ;;
    *)
        echo "[x] Sorry, this arch compile failed, please read README.md !!"
        exit 1
        ;;
esac

if [ -z ${KERNEL_VERSION} ] || [ ${KERNEL_VERSION} = "" ]; then
    echo "[x] Can't identify kernel version!!!"
    exit 0
fi

cd ${KERNEL_AND_MODULE_DIR}
${KERNEL_AND_MODULE_DIR}/run ${ARCH} ${KERNEL_VERSION}
cd -
if [ -e "${KERNEL_DIR}/${ARCH}/${KERNEL_VERSION}/${KERNEL_NAME}" ]; then
    echo "true" > "${SCRATCH_IID}/buildKernel"
else
    echo "false" > "${SCRATCH_IID}/buildKernel"
fi

exit 0

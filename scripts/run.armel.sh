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
    echo "Usage: run.armel.sh <image ID>"
    exit 1
fi
IID=${1}
QEMU_INIT=${2}

WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
KERNEL=`get_kernel ${IID} false`
QEMU_MACHINE=`get_qemu_machine ${IID}`
QEMU_ROOTFS=`get_qemu_disk ${IID}`

if (${FIRMAE_NETWORK}); then
  QEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev user,id=net0"
else
  QEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev socket,id=net0,listen=:2000 -device virtio-net-device,netdev=net1 -netdev socket,id=net1,listen=:2001 -device virtio-net-device,netdev=net2 -netdev socket,id=net2,listen=:2002 -device virtio-net-device,netdev=net3 -netdev socket,id=net3,listen=:2003"
fi

if [[ ${QEMU_MACHINE} == *"vexpress-a9"* ]]; then
  QEMU_NETWORK="-net nic,model=lan9118,vlan=0 -net user,vlan=0"
fi

if [[ ${QEMU_MACHINE} == *"vexpress-a9"* ]]; then
  QEMU_AUDIO_DRV=none qemu-system-arm -m 256 -M ${QEMU_MACHINE} -kernel ${KERNEL} -drive if=sd,driver=file,filename=${IMAGE} -append "firmadyne.syscall=1 root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${QEMU_INIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NETWORK=${FIRMAE_NETWORK} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=31" -serial file:${WORK_DIR}/qemu.initial.serial.log -serial unix:/tmp/qemu.${IID}.S1,server,nowait -monitor unix:/tmp/qemu.${IID},server,nowait -display none ${QEMU_NETWORK}
else
  QEMU_AUDIO_DRV=none qemu-system-arm -m 256 -M ${QEMU_MACHINE} -kernel ${KERNEL} -drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs -append "firmadyne.syscall=1 root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${QEMU_INIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NETWORK=${FIRMAE_NETWORK} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=31" -serial file:${WORK_DIR}/qemu.initial.serial.log -serial unix:/tmp/qemu.${IID}.S1,server,nowait -monitor unix:/tmp/qemu.${IID},server,nowait -display none ${QEMU_NETWORK}
fi

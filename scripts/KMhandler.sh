#!/bin/sh

echo "[*] FirmSE: Kernel module insertion."

BUSYBOX=/firmadyne/busybox

echo "[-] /proc kernel module"
for module in `ls /firmadyne/file_ko`
do
    echo "> $module"
    ${BUSYBOX} insmod "/firmadyne/file_ko/$module"
done

echo "[-] /dev kernel module"
for dev in `cat /firmadyne/md_list`
do
	echo "> ${dev}.ko"
	${BUSYBOX} insmod "/firmadyne/md_ko/$dev.ko"
	major_id=`cat /proc/devices | grep $dev | awk '{print $1}'`
	if [ -f "/dev/${dev}" ]; then
		rm -f /dev/${dev}
	fi
	${BUSYBOX} mknod "/dev/${dev}" c $major_id 0
done

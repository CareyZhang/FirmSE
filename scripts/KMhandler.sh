#!/bin/sh
###################################################
###	Bring up kernel module and device	###
###################################################

BUSYBOX=/firmadyne/busybox

for module in `ls /firmadyne/file_ko`
do
    ${BUSYBOX} insmod "/firmadyne/file_ko/$module"
done

for dev in `cat /firmadyne/md_list`
do
	${BUSYBOX} insmod "/firmadyne/md_ko/$dev.ko"
	major_id=`cat /proc/devices | grep $dev | awk '{print $1}'`
	if [ -f "/dev/${dev}" ]; then
		rm -f /dev/${dev}
	fi
	${BUSYBOX} mknod "/dev/${dev}" c $major_id 0
done

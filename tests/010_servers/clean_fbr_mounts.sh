#!/bin/bash

for fiber_mount in `cat /proc/mounts | grep "^fiberfs " | awk '{print $2}'`
do
	echo "Found fiber: $fiber_mount"

	echo "Checking /sys/fs/fuse/connections"
	fuse_conn=$(timeout 1 stat -c %d $fiber_mount 2>/dev/null)

	echo "Attempting umount"
	sudo timeout 5 umount $fiber_mount

	if [ "$fuse_conn" == "" ]
	then
		echo "No /sys/fs/fuse/connections entry found..."
		continue
	fi

	if [ -d /sys/fs/fuse/connections/$fuse_conn ]
	then
		echo "Found fuse connection: $fuse_conn"
		echo 1 | sudo tee /sys/fs/fuse/connections/$fuse_conn/abort
	fi
done

if [ "$(timeout 1 ls -d /tmp/_fbr* 2>/dev/null)" == "" ]
then
	echo "No fiber tmps found"
fi

for tmp_dir in `timeout 1 ls -d /tmp/_fbr* 2>/dev/null`;
do
	echo "Found tmp: $tmp_dir"
	rm -rf $tmp_dir
done

for log_dir in `ls -d /dev/shm/fiberfs* 2>/dev/null`;
do
	echo "Found log: $log_dir"
	rm $log_dir
done

find /sys/fs/fuse/connections/* -type d 2>/dev/null

pgrep -af fiberfs

#!/bin/bash

MALWARE_NAME=$1
ROOT_DIR=$2
FS_DIR=$ROOT_DIR/filesystem
ORIGINAL_FS=$FS_DIR/openwrt-malta-be-root.ext4
NEW_FS=$FS_DIR/$MALWARE_NAME.ext4
MOUNT_FOLDER=`mktemp -d`
# Create the new filesystem and mount to tmp folder under filesystem
cp $ORIGINAL_FS $NEW_FS && mount $NEW_FS $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    echo $MOUNT_FOLDER
else
    echo "FAIL"
fi

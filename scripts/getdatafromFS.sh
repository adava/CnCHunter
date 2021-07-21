#!/bin/bash

ROOT_DIR=$1
malware=$2
MOUNT_FODLER=$3
GOT_DATA=$4

mkdir -p $MOUNT_FODLER

if [ "$GOT_DATA" == "NO" ]; then
    mount $ROOT_DIR/filesystem/$malware.ext4 $MOUNT_FODLER
    if [ $? -eq 0 ] && [ "$GOT_DATA" == "NO" ]; then
        cp -r $MOUNT_FODLER/analysis  $ROOT_DIR/
        GOT_DATA="YES"
    else
        $ROOT_DIR/script/getdatafromFS.sh $ROOT_DIR $malware $MOUNT_FODLER $GOT_DATA
    fi
fi
if [ "$GOT_DATA" == "YES" ]; then
    if [ "$(ls -A $MOUNT_FODLER)" ]; then
        umount $MOUNT_FODLER
        if [ $? -eq 0 ]; then
            rm -rf $MOUNT_FODLER && rm $ROOT_DIR/filesystem/$malware.ext4
        else
            $ROOT_DIR/script/getdatafromFS.sh $ROOT_DIR $malware $MOUNT_FODLER $GOT_DATA
        fi
    else
        rm -rf $MOUNT_FODLER && rm $ROOT_DIR/filesystem/$malware.ext4
    fi
fi

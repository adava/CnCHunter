#!/bin/bash

MALWARE_NAME=$1
ITERATION=$2
ROOT_DIR=$3
EXPERIMENT_TIME=$4
AUGMENTATION=$5
FIRMWARE_AUGMENTATION=$6
MOUNT_FOLDER=$7
FS_DIR=$ROOT_DIR/filesystem
ORIGINAL_FS=$FS_DIR/openwrt-malta-be-root.ext4
NEW_FS=$FS_DIR/$MALWARE_NAME.ext4
TARGET_IP=${8:-}
TARGET_PORT=${9:-}
CnC_REDIRECT=${10:-}
if [[ $MALWARE_NAME == *victim* ]]; then
   FIRMWARE_AUGMENTATION="NO"
   AUGMENTATION="NO"
fi

# put firmware stuff in FS
if [ $FIRMWARE_AUGMENTATION == "YES" ]; then
    `/bin/sh $ROOT_DIR/augment/$MALWARE_NAME/firmware_${ITERATION}_$MALWARE_NAME.sh $MOUNT_FOLDER`
fi

# Stage malware in filesystem
$ROOT_DIR/scripts/stage_malware.sh $ROOT_DIR $MALWARE_NAME
cp -r $ROOT_DIR/malware/$MALWARE_NAME $MOUNT_FOLDER/

# Augmentation script
if [ $AUGMENTATION == "YES" ]; then
    cp $ROOT_DIR/augment/$MALWARE_NAME/${ITERATION}_$MALWARE_NAME.sh $MOUNT_FOLDER
else
   cat >  $MOUNT_FOLDER/${ITERATION}_$MALWARE_NAME.sh << EOF
#!/bin/sh
echo "all good"
EOF
fi

chmod +x $MOUNT_FOLDER/${ITERATION}_$MALWARE_NAME.sh

# Create the runRARE script to run the malware after a sleep time
cat > $MOUNT_FOLDER/done.sh << EOF
#!/bin/sh
sleep $EXPERIMENT_TIME && /$MALWARE_NAME/killAll.sh; iptables -F && /etc/init.d/dropbear start && echo ok > /all_done
EOF

cat > $MOUNT_FOLDER/etc/runRARE.sh << EOF
#!/bin/sh
sleep 20
/done.sh &
/bin/sh /${ITERATION}_$MALWARE_NAME.sh &
cd /$MALWARE_NAME; ./script.sh $MALWARE_NAME $ITERATION &
EOF

chmod +x $MOUNT_FOLDER/etc/runRARE.sh $MOUNT_FOLDER/done.sh

if [[ $TARGET_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    cat > $MOUNT_FOLDER/etc/rc.local << EOF
    #CnC Hunter redirection
    iptables -t nat -A OUTPUT -p tcp -d $TARGET_IP --dport $TARGET_PORT -j DNAT --to-destination $CnC_REDIRECT
    /etc/runRARE.sh
    exit 0
EOF
elif [[ ! -z $TARGET_IP ]]
then
cat > $MOUNT_FOLDER/etc/rc.local << EOF
    #CnC Hunter redirection
    echo "$CnC_REDIRECT $TARGET_IP" >> /etc/hosts
    /etc/runRARE.sh
    exit 0
EOF
else
    cat > $MOUNT_FOLDER/etc/rc.local << EOF
    # Put your custom commands here that should be executed once
    # the system init finished. By default this file does nothing.
    /etc/runRARE.sh
    exit 0

EOF
fi

# Finish up
umount $MOUNT_FOLDER
rm -rf $ROOT_DIR/malware/$MALWARE_NAME
# return the tmp folder for getting data out


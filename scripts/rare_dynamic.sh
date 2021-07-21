#!/bin/sh

ABS_PATH=$1
PCAP_DIR=$2
FS_FILE=$3
DEBIAN=$4
MAC_ADDR=$5
screen -dmS CnCHunter ${ABS_PATH}/scripts/run_qemu.sh ${PCAP_DIR} ${FS_FILE} ${DEBIAN} ${ABS_PATH} ${MAC_ADDR}

#!/bin/sh
CUR_DIR=`pwd`
TMP_PS=$CUR_DIR/.tmp_ps
ps aux > $TMP_PS
if ln $TMP_PS $TMP_PS.lock 2>&-; then
   echo "Killing openwrt"
   for openwrt_id in `grep openwrt $TMP_PS | awk ' { print $2;}'`; do
      kill -9 $openwrt_id 2>/dev/null
   done
   echo "Killing tcpreplay now"
   for tcpreplay_id in `grep tcpreplay $TMP_PS | awk ' { print $2;}'`; do
      kill -9 $tcpreplay_id 2>/dev/null
   done
   echo "Killing all other tcpdumps"
   for tcpdump_id in `grep tcpdump $TMP_PS | awk ' { print $2;}'`; do
      kill -9 $tcpdump_id 2>/dev/null
   done
   echo "Killing all pcapdiffcsv.py files"
   for pcapdiff_id in `grep pcapdiff2csv $TMP_PS | awk ' { print $2;}'`; do
      kill -9 $pcapdiff_id 2>/dev/null
   done
   echo "Killing all ssh connection to router"
   for ssh_id in `grep 192.168.1.1 $TMP_PS |awk ' { print $2;}'`; do
      kill -9 $ssh_id 2>/dev/null
   done
   echo "Clearing netconfig"
   $CUR_DIR/scripts/stop_network.sh
   #echo "in case anything is left: pids file"
   #kill -9 `cat pids`
   rm -rf $CUR_DIR/pcaps/stage
   rm -rf $CUR_DIR/malware/MIPS-*

   #delete the partially created filesystem (stop_instance wouldn't do the job for quick INTs)
   echo "deleting the partially created filesystems"
   find ./filesystem/ -type f -cmin -1 -delete
   echo "Killing all the processes for process run.py"
   for main in `grep run.py $TMP_PS | awk ' { print $2;}'`; do
      kill -9 $main 2>/dev/null
   done

   rm $TMP_PS
   rm $TMP_PS.lock
fi
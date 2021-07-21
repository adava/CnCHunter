#!/bin/bash

file=$1
pid=$$
for malware_id in `ps aux | grep $file | grep -v grep | awk ' { print $2;}'`; do
     if [ "$malware_id" != "$pid" ]; then
          sudo kill -9 $malware_id 2>/dev/null
     fi
done

# screen -wipe

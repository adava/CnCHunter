#!/bin/bash
#make sure tshark is installed, the script wouldn't tell
PCAP_FILE=$1
ip=`tshark -r $PCAP_FILE -Y "bootp.option.type == 54 and udp.dstport == 68" -T fields -e ip.dst 2>/dev/null |tail -n 1`
#echo $ip
if [[ ${ip} =~ ^192.168.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
# tshark -r $PCAP_FILE -Y "ip.src == $ip && tcp" -T fields -e tcp.dstport 2>/dev/null
 echo "$ip"
else
 echo "False"
fi

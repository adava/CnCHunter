#!/bin/sh

if test -e "/proc/sys/net/ipv4/conf/br-wan"; then
    sudo ip link set br-wan down
fi

sudo sysctl -w net.ipv4.ip_forward=0

if test -e "/proc/sys/net/ipv4/conf/br-wan/proxy_arp"; then
    sudo sysctl -w net.ipv4.conf.br-wan.proxy_arp=0
fi

for i in $( sudo iptables -t nat --line-numbers -L | grep ^[0-9] | awk '{ print $1 }' | tac ); do sudo iptables -t nat -D POSTROUTING $i; done

if test -e "/proc/sys/net/ipv4/conf/br-wan"; then
    sudo ip link delete br-wan
fi


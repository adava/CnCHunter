#!/bin/sh
BR_WAN="br-wan"
IF_INET="enp0s3"
# setup bridge for LAN network
# sudo ip link add dev "$BR_LAN" type bridge
# sudo ip link set dev "$BR_LAN" up
# sudo ip addr add 192.168.1.3 dev "$BR_LAN"
# sudo ip route add 192.168.1.0/24 dev "$BR_LAN"

# setup bridge for WAN network
sudo ip link add dev "$BR_WAN" type bridge
sudo ip addr add 192.168.0.1 dev "$BR_WAN"
sudo ip link set dev "$BR_WAN" up
#sudo ip link set dev tap0 master "$BR_WAN"
sudo ip route add 192.168.0.0/16 dev "$BR_WAN"

# Internet access setup
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf."$BR_WAN".proxy_arp=1
sudo iptables -t nat -A POSTROUTING -o "$IF_INET" -j MASQUERADE

sudo /etc/init.d/dnsmasq restart

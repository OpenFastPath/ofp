#!/bin/bash
intf=$1
if test "X$intf" = "X"; then intf=eth0; fi

./example/fpm/fpm -i $intf -c 4 &

sleep 3
iptables -A FORWARD -i $intf -j DROP
iptables -A INPUT -i $intf -j DROP
ip6tables -A FORWARD -i $intf -j DROP
ip6tables -A INPUT -i $intf -j DROP
ifconfig $intf -arp
ip addr flush dev $intf
sleep 3
sysctl -w net.ipv6.conf.fp0.autoconf=0
dhclient -v fp0
#sysctl -w net.ipv4.conf.fp0.forwarding=0
#sysctl -w net.ipv4.conf.fp0.mc_forwarding=0
#sysctl -w net.ipv4.conf.fp0.arp_filter=0
#sysctl -w net.ipv4.conf.fp0.arp_accept=0
#sysctl -w net.ipv4.conf.fp0.arp_announce=1

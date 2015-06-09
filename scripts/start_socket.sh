#!/bin/bash -x

intf=$1
if test "X$intf" = "X"; then intf=eth0; fi

./example/socket/socket -i $intf -c 2 -f ./example/socket/ofp.conf &

sleep 3
iptables -A FORWARD -i $intf -j DROP
iptables -A INPUT -i $intf -j DROP
ip6tables -A FORWARD -i $intf -j DROP
ip6tables -A INPUT -i $intf -j DROP
ifconfig $intf -arp
ip addr flush dev $intf
sleep 3
sysctl -w net.ipv6.conf.fp_$intf.autoconf=0

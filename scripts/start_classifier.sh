#!/bin/bash -x

intf=$1
if test "X$intf" = "X"; then intf=eth0; fi

iptables -A FORWARD -i $intf -j DROP
iptables -A INPUT -i $intf -j DROP
ip6tables -A FORWARD -i $intf -j DROP
ip6tables -A INPUT -i $intf -j DROP
ifconfig $intf -arp
ip addr flush dev $intf

sleep 1

./example/classifier/classifier -i $intf -c 2 -f ./example/classifier/ofp.conf &

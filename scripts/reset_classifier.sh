#!/bin/bash -x

intf=$1
if test "X$intf" = "X"; then intf=eth0; fi

killall classifier
sudo iptables -D FORWARD -i $intf -j DROP
sudo iptables -D INPUT -i $intf -j DROP
sudo ip6tables -D FORWARD -i $intf -j DROP
sudo ip6tables -D INPUT -i $intf -j DROP
sudo ifconfig $intf arp
sudo ifdown $intf && sudo ifup $intf

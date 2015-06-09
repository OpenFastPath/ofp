#!/bin/bash -x

intf=$1
if test "X$intf" = "X"; then intf=eth0; fi
echo Running FPM on intferface $intf

killall fpm
sudo iptables -D FORWARD -i $intf -j DROP
sudo iptables -D INPUT -i $intf -j DROP
sudo ip6tables -D FORWARD -i $intf -j DROP
sudo ip6tables -D INPUT -i $intf -j DROP
sudo ifconfig $intf arp
sudo dhclient -v $intf

# restore DNS servers:
#cat resolv.conf.reference |sudo tee /etc/resolv.conf
echo nameserver 8.8.8.8 |sudo tee /etc/resolv.conf
echo nameserver 127.0.1.1 |sudo tee -a /etc/resolv.conf
cat /etc/resolv.conf

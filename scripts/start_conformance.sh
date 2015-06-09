#!/bin/bash
./example/fpm/fpm -i vlan103,vlan104 -c 4 &

sleep 3
iptables -A FORWARD -i vlan103 -j DROP
iptables -A FORWARD -i vlan104 -j DROP
iptables -A INPUT -i vlan103 -j DROP
iptables -A INPUT -i vlan104 -j DROP
ifconfig vlan103 -arp
ifconfig vlan104 -arp
ip addr flush dev vlan103
ip addr flush dev vlan104
#sleep 1
#sysctl -w net.ipv6.conf.fp_vlan103.autoconf=0
#sysctl -w net.ipv6.conf.fp_vlan104.autoconf=0
sleep 1
ifconfig fp0 192.168.13.15 up
ifconfig fp1 192.168.14.15 up
# arp of ixia machine is required for sending ICMP Echo Req in tests 1.3 and 4.4
arp -i fp0 -s 192.168.13.16 10:1F:74:36:29:9A

#!/bin/bash -x

killall fpm

sleep 3

sudo iptables -D FORWARD -i vlan103 -j DROP
sudo iptables -D FORWARD -i vlan104 -j DROP
sudo iptables -D INPUT -i vlan103 -j DROP
sudo iptables -D INPUT -i vlan104 -j DROP
sudo ifconfig vlan103 arp
sudo ifconfig vlan104 arp


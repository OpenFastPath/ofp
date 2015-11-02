#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "requires an interface parameter. Use: ./start_webserver.sh ethX"
    exit -1
fi

intf=$1
if test "X$intf" = "X"; then intf=eth0; fi

killall webserver
sudo iptables -D FORWARD -i $intf -j DROP
sudo iptables -D INPUT -i $intf -j DROP
sudo ip6tables -D FORWARD -i $intf -j DROP
sudo ip6tables -D INPUT -i $intf -j DROP
sudo ifconfig $intf arp

# restore DNS servers:
#cat resolv.conf.reference |sudo tee /etc/resolv.conf
echo nameserver 8.8.8.8 |sudo tee /etc/resolv.conf
echo nameserver 127.0.1.1 |sudo tee -a /etc/resolv.conf
cat /etc/resolv.conf


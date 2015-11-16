#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "requires two parameters. Use: ./start_webserver.sh ethX IP"
    exit -1
fi

intf=$1
echo Starting Web Server on interface $intf

www_dir="${www_dir:-"/var/www/"}"
export www_dir
./example/webserver/webserver -i $intf -c 2 &

sleep 1

ifconfig fp0 $2

sleep 1
iptables -A FORWARD -i $intf -j DROP
iptables -A INPUT -i $intf -j DROP
ip6tables -A FORWARD -i $intf -j DROP
ip6tables -A INPUT -i $intf -j DROP
ifconfig $intf -arp
ip addr flush dev $intf


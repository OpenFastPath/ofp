#!/bin/bash

# Use this script to block access to a linux interface for other
# applications before it is utilized as a socket pktio, in OFP
# example applications.

# Check arguments
if [ "$#" -ne 1 ]; then
	echo "Error: Invalid number of parameters."
	echo "Usage:"
	echo "  "${0}" <interface_name>"
	exit 1
fi

linux_intf=${1}
ifconfig $linux_intf &> /dev/null
if [ $? -ne 0 ]; then
	echo "Error: Invalid interface '"$linux_intf"'."
	exit 1
fi

# Check rights
if [ "$EUID" -ne 0 ]; then
	echo "Error: Script must be executed with superuser rights."
	exit 1
fi

# Set iptables: append drop rules
iptables -A FORWARD -i $linux_intf -j DROP
iptables -A INPUT -i $linux_intf -j DROP
ip6tables -A FORWARD -i $linux_intf -j DROP
ip6tables -A INPUT -i $linux_intf -j DROP

# Disable arp
ifconfig $linux_intf -arp

# Flush addresses
ip addr flush dev $linux_intf

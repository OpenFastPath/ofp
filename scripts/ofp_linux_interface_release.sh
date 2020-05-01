#!/bin/bash

# Use this script to restore access to a linux interface for other
# applications after it was blocked with ofp_linux_interface_acquire.sh.

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

# Set iptables: delete drop rules
iptables -D FORWARD -i $linux_intf -j DROP
iptables -D INPUT -i $linux_intf -j DROP
ip6tables -D FORWARD -i $linux_intf -j DROP
ip6tables -D INPUT -i $linux_intf -j DROP

# Enable arp
ifconfig $linux_intf arp

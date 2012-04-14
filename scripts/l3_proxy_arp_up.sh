#!/bin/sh

if [ $# -ne 2 ]
then
	echo "Usage: $0 <source interface> <dest interface>"
	exit
fi

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.$1.proxy_arp=1
sudo sysctl -w net.ipv4.conf.$2.proxy_arp=1
sudo iptables -t filter -F
sudo iptables -A FORWARD -i $1 -o $2 -j ACCEPT

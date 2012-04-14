#!/bin/sh

if [ $# -ne 2 ]
then
	echo "Usage: $0 <src interface> <dest interface>"
	exit
fi

sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.conf.$1.proxy_arp=0
sudo sysctl -w net.ipv4.conf.$2.proxy_arp=0
sudo iptables -t filter -F

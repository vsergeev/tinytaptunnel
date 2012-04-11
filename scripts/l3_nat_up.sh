#!/bin/sh

if [ $# -ne 2 ]
then
	echo "Usage: $0 <source interface> <dest interface>"
	exit
fi

sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t filter -F
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -j MASQUERADE -o $2
sudo iptables -A FORWARD -i $1 -o $2 -j ACCEPT

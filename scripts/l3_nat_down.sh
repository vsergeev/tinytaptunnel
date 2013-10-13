#!/bin/sh

sudo sysctl -w net.ipv4.ip_forward=0
sudo iptables -t filter -F
sudo iptables -t nat -F

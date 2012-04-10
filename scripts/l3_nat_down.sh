#!/bin/sh

sysctl -w net.ipv4.ip_forward=0

iptables -t filter -F
iptables -t nat -F

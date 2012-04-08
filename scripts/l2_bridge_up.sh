#!/bin/sh

if [ $# -ne 2 ]
then
	echo "Usage: $0 <1st interface> <2nd interface>"
	exit
fi

sudo brctl addbr vpnbridge
sudo brctl stp vpnbridge off
sudo brctl addif vpnbridge $1
sudo brctl addif vpnbridge $2
sudo ifconfig vpnbridge up

#!/bin/sh

sudo ifconfig vpnbridge down
sudo brctl delbr vpnbridge

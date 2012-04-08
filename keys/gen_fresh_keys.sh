#!/bin/sh
openssl genrsa -out key1_pri.pem 2048
openssl genrsa -out key2_pri.pem 2048
openssl rsa -in key1_pri.pem -pubout > key1_pub.pem
openssl rsa -in key2_pri.pem -pubout > key2_pub.pem

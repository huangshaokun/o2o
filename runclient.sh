#!/bin/sh

go run ./client -s=127.0.0.1:2399 -key=1234 -p=2345:192.168.1.241:5000
# go run ./client -s=127.0.0.1:2399 -key=1234 -p=2345:ip.lyl.hk:80
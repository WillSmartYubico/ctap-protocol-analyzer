#!/bin/bash
lsusb=$(ssh pi@raspberrypi.local lsusb | grep -vi hub$ | head -1 | egrep -o '[0-9a-f]{4}:[0-9a-f]{4}')
V=$(echo $lsusb | cut -d: -f1)
P=$(echo $lsusb | cut -d: -f2)
set -x
ssh pi@raspberrypi.local -L 5678:localhost:5678 sudo usb-mitm -v $V -p $P -z

#!/bin/bash
IP=$1
if [ -z "$IP" ]; then
  echo Searching for multicast on 239.255.0.0/16:4321...
  IP=$(sudo ./snooper.py 2>/dev/null | head -1 | sed 's/.*\(239\.255\..*\)__.*/\1/')
  echo Found $IP:4321
else
  echo Using $IP:4321
fi
gst-launch-1.0 -v udpsrc address=$IP auto-multicast=true port=4321 skip-first-bytes=9 ! audio/x-raw,channels=2,rate=48000,format=S24BE ! audioconvert ! autoaudiosink

# gst-dante-flow

Listen to an Audinate Dante stereo multicast flow with gstreamer. Tested with Dante Via.

## Requirements

git clone https://github.com/Dregu/gst-dante-flow
sudo pacman -S python2-pcapy impacket

## Listen

```./listen.sh [239.255.x.x]``` plays the first multicast found on 239.255.0.0/16:4321 or the specified ip.

You can use ```sudo ./snooper.py``` (console) or ```sudo mcscanner``` (gtk) to find a specific multicast flow.
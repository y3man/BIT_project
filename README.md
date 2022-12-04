# Scanner #

Scanner is a short script which will turn wireless card to listening mode, dump all trafic, analyze it for deauthentication frames and notify user when found.
Program creates some temporary files which are removed after they are no longer needed.

In each cycle (user can specify its length) the scanner listnes to all traffic and dumps it into a .cap file. After the cycle ends, the cap file is analyzed. If there are no findings the cycle repeats itself indefinitely.

Findings are reported to the terminal. Current working cap file is moved to 'deauths.cap', indexes and source addresses are exported to export.json and program quits.

## Requirements ##

- python3
- scapy (`pip install scapy`)
- must run with root privileges

## Usage ##

Run `python3 scanner.py -h` for help message.

Find out SSID of your wireless network.

Find out the name of your wireless device (f.e. with `iwconfig`)

Parameters:

- -d / --device {device} - wireless interface name (default = wlan0)
- -t / --timer {seconds} - period of listening before analyzing the result (default = 30)
- -s / --ssid {ssid} - name of your wireless network (required)
- -a / --analyze {file name} - static analysis of a file

## Examples ##

`sudo python3 scanner.py -s MyWifi -t 60` - running scanner in 60 second cycles on 'MyWifi' network.

`sudo python3 scanner.py -s MyWifi` - same as before but with default cycle of 30 seconds.

`python3 scanner.py -a deauths.cap` - scans the 'deauths.cap' file for deauthentication frames.
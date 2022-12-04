import subprocess
import sys
from time import sleep
from analyzer import analyze
import json
import os
import signal

class Device:
	def __init__(self, name: str):
		self.name = name
		assert (self.setup()), "Could not lock in the device"
	def setup(self) -> bool:
		try:
			subprocess.run("airmon-ng check kill", shell=True, check=True)
		except subprocess.CalledProcessError:
			return False
		try:
			subprocess.run(f"airmon-ng start {self.name}", shell=True, check=True)
		except subprocess.CalledProcessError:
			return False
		self.name += "mon"
		return True
	def __str__(self) -> str:
		return str(self.name)
	def __del__(self):
		subprocess.run(f"airmon-ng stop {self.name}", shell=True)

def help():
	help = """Scanner is a short script which will turn wireless card to listening mode, dump all trafic, analyze it for deauthentication frames and notify user when found.
	scapy package is required (run 'pip install scapy').
	Usage:
		Run the scanner.py.
		Parameters:
			-d / --device {device} - wireless interface name (default = wlan0)
			-t / --timer {seconds} - period of listening before analyzing the result (default = 30)
			-s / --ssid {ssid} - name of your wireless network (required)
		Run 'scanner.py -a {file name}' for static analysis of a pcap file.
	SUDO privileges are required.
	
	Output is saved to 'deauths.cap' and 'export.json' files. Program is stopped after finding deauthentication frames."""
	print(help)
	
	
def monitor(device_name: str, ssid: str, timer: int):
	device = Device(device_name)
	if not device:
		return
	subprocess.run("rm ./capture* -f", shell=True)
	while True:
		dump = subprocess.Popen(f"airodump-ng -w 'capture' --essid {ssid} {device}", shell=True, preexec_fn=os.setsid)
		sleep(timer)
		os.killpg(os.getpgid(dump.pid), signal.SIGTERM)

		found = analyze("capture-01.cap")

		if len(found) > 0:
			print("Deauths found\nOutput saved")
			with open("export.json", "w") as outfile:
				json.dump(found, outfile)
			subprocess.run("mv capture-01.cap deauths.cap", shell=True)
			subprocess.run("rm ./capture* -f", shell=True)
			return
		subprocess.run("rm ./capture* -f", shell=True)

def main(args):
	device = "wlan0"
	timer = 30
	ssid = None
	
	for i, arg in enumerate(args):
		match arg:
			case "-d" | "--device":
				device = args[i+1]
			case "-t" | "--timer":
				timer = int(args[i+1])
			case "-s" | "--ssid":
				ssid = args[i+1]
			case "-a" | "--analyze":
				found = analyze(args[i+1])
				if len(found) != 0:
					print(found)
				else:
					print("All clear")
				return
			case "-h" | "--help":
				help()
				return
				
	if not ssid:
		print("SSID is required")
		return

	monitor(device, ssid, timer)
		
if __name__ == "__main__":
	main(sys.argv)
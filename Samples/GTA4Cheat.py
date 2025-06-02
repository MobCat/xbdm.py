#!/usr/bin/env python3
#! MobCat 2025

'''
 An example of a RTM tool for GTA 4.
 This code is intended for 
 Title ID: 545407F2
 Title Update: 5, 6 and 8.

 Every 1 sec this code will check if your health and armor is below the max amount
 if it is below the max, this code will reset your health and armor back to the max amount.
 See here for more codes you might want to test out
 https://mobcat.zip/codebook/index.php?titleID=545407F2
'''

import xbdm # Remember to place the xbdm.py code in the same dir as this script
import sys
import struct
import time

if len(sys.argv) < 2:
	#
	print("Usage: python GTA4Cheat.py console_ip")
	sys.exit(1)

console_ip = sys.argv[1]
xbdm = xbdm.XBDMClient(console_ip)

if xbdm.open_connection():
	print(f"Connected to {xbdm.get_debug_name()}@{console_ip}")
	print(xbdm.x_notify("NULL", "GTA 4 RTM has connected"))
	print("Entering the health cheat loop now.")

while True:
	Health = struct.unpack('>f', xbdm.get_memory(0xDB3D1444, 4))[0]
	Armor  = struct.unpack('>f', xbdm.get_memory(0xDB3D1C38, 4))[0]
	if Health < 200 or Armor < 100 :
		xbdm.set_memory(0xDB3D1444, struct.pack('>f', 200))
		xbdm.set_memory(0xDB3D1C38, struct.pack('>f', 100))
		print(f'Health Was {Health} is {struct.unpack('>f', xbdm.get_memory(0xDB3D1444, 4))[0]}')
	else:
		print("Health Is 200")
	time.sleep(1)
#!/usr/bin/env python3
#! MobCat 2025

'''
This sample will display a bunch of info about your xbox and it's running titles.
This sample uses both XBDM and JRPC commands, so you will need both loaded to use this.

'''

import xbdm
import sys
import time


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python SysInfo.py console_ip")
        #TODO: If no ip was provided, look for XBDM servers
        #"send a Type 3 NAP packet with no name (length 0) to the UDP address 255.255.255.255:731"
        #TODO: Allow for connecting with debug name as well, using the UDP lookup
        sys.exit(1)
    
    console_ip = sys.argv[1]
    xbdm = xbdm.XBDMClient(console_ip)
    
    if xbdm.open_connection():
        print(f"Connected to {xbdm.get_debug_name()}@{console_ip}")
        xbdm.x_notify("READY_TO_PLAY","SysInfo connected")
        
        # Get system information
        sys_info = xbdm.get_system_information()
        print(f"""Sysinfo:\n  System: {sys_info.system}
  CPU: {sys_info.platform}
  CPU Key: {xbdm.get_cpukey()}
  Type: {sys_info.type}
  Kernel Version: {sys_info.kernel_version}
  XBDM Version: {xbdm.get_dmv()}
  HDD Enabled: {sys_info.hdd_enabled}""")

        # Console temps
        #BUG: GPU is being reported as CPU.
        print(f"""
Temps: 
  CPU: {xbdm.get_Temp('CPU')}°c
  GPU: {xbdm.get_Temp('GPU')}°c
  MEM: {xbdm.get_Temp('MEM')}°c
  Chassis: {xbdm.get_Temp('CHS')}°c
  """)
        
        # List drives
        drives = xbdm.get_drives()
        print("\nDrives:")
        for drive in drives:
            free_gb = drive.free_bytes_available / (1024 * 1024 * 1024)
            total_gb = drive.total_bytes / (1024 * 1024 * 1024)
            print(f"  {drive.friendly_name}: {free_gb:.2f} GB free of {total_gb:.2f} GB")

        # Running title
        #TODO: Get info like title name, ver, TU, mem used / ranges.
        # You can see ranges from the loaded modules code though. 
        # You just have to know the name of your xbx you are running
        print(f"""
Title Info:
  Title ID: {xbdm.get_TitleID()}""")
        

        # List running modules/plugins
        print("\nLoaded Modules:")
        modules = xbdm.get_loaded_modules()
        for i, module in enumerate(modules):
            print(f"  {module.name} (Base: 0x{module.base_address:08x}, Size: 0x{module.size:08x})")
        
        
        # Close the connection
        xbdm.close_connection()
        print("\n-Connection closed-")
    else:
        print(f"Failed to connect to Xbox 360 at {console_ip}")
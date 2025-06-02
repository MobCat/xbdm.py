# xbdm.py
Xbox 360 XBDM/JRPC Python Client

A Python implementation for connecting to and communicating with an <br>Xbox 360 Devkit/JTAG/RGH/BadUpdate via the Xbox Debug Monitor (XBDM) protocol.<br>
So we can use our favorite scripting language to easily and quickly peek and poke into your xbox without needing to build a whole C# project.<br>
This library also contains commands for connecting to JRPC Version 2. There are just some things JRPC does better and easier.<br>
So gonna make this a combo library. The JRPC commands are marked as such and you don't have to use them if you don't want to.<br>

> [!NOTE]  
> This project is incompleate. it works, but its not "ready for prod" yet<br>
> There are still some functions left to port, and console types to test.

# Pre-requirements
- A modifyed or devkit xbox (If modifyed you need to be running the `xbdm.xbx` and `jrpc.xbx` plugins)
- Pyhton 3.13.3 or higher.
- Python libs (socket, struct, re, enum and typing)(Yes, I should make a requirements.txt..)

# Basic setup / use
1. Download the `xbdm.py` script and place it in the same dir as your python script you are working on.
2. wright some sample code like
```python
import xbdm # Importing the xbdm.py script from this dir.

console_ip = "192.168.1.20" # Replace with your consoles IP
xbdm = xbdm.XBDMClient(console_ip) # Setup a new xbdm connection

if xbdm.open_connection(): # If connected, do things.
    print(f"Connected to {xbdm.get_debug_name()}@{console_ip}")
    xbdm.x_notify("NULLED","Sample code loaded and connected")
    print(f"Your cpu key is {xbdm.get_cpukey()}")
else: # Else, don't do things.
    print(f"Failed to connect to Xbox 360 at {console_ip}")
```
3. `python sample.py` to run your sample code, and if the console IP is right and evereything is setup corectly<br>
The console should display a notification.

See the `Samples` folder for more indepth code on what this library can do right now.

# TODO:
As stated, this code is unfinished, but it works.<br>
Only about 80% of JRPC is ported right now, and about 30% of XBDM needs more testing and work.<br>
This library is kinda hacked together but it did what I wanted it to, but it needs more work<br>
before it's "ready for prod". But you might get some use out of it, even in it's unfinished state.

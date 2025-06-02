#!/usr/bin/env python3.10.4
#! MobCat 2025
"""
Xbox 360 XBDM/JRPC Client

A Python implementation for connecting to and communicating with an Xbox 360 devkit/JTAG/RGH/BadUpdate via the Xbox Debug Monitor (XBDM) protocol.
This library also contains commands for connecting to JRPC Version 2. There are just some things JRPC does better and easier.
So gonna make this a combo library. The JRPC commands are marked as such and you don't have to use them if you don't want to.

References:
    https://github.com/Experiment5X/XBDM/blob/master/Xbdm.cpp
    https://github.com/XboxChef/JRPC/blob/master/JRPC_Client/JRPC.cs
"""

import socket
import struct
import time
import os
import re #regex will be the death of me. Such a hacky way to fix things.
from enum import Enum, auto
from typing import Tuple, List

class ResponseStatus(Enum):
    # Status codes returned by XBDM commands
    # Kinda the same as HTML, 200s are ok, 400s are errors.
    OK                  = 200 # Standard response for successful execution of a command.
    Connected           = 201 # Initial response sent after a connection is established. The client does not need to send anything to solicit this response.
    Multiline           = 202 # The response line is followed by one or more additional lines of data terminated by a line containing only a . (period). The client must read all available lines before sending another command.
    Binary              = 203 # The response line is followed by raw binary data, like a screenshot, the length of which is indicated in some command-specific way. The client must read all available data before sending another command.
    ReadyToAcceptData   = 204 # The command is expecting additional binary data from the client. After the client sends the required number of bytes, XBDM will send another response line with the final result of the command.
    ConnectionDedicated = 205 # The connection has been moved to a dedicated handler thread.
    Error               = 400 # Unexpected error. An internal error occurred that could not be translated to a standard error code. The message is typically more descriptive, such as "out of memory" or "bad parameter".
    MaxConns            = 401 # Max number of connections exceeded. The connection could not be established because XBDM is already serving the maximum number of clients (4).
    FileNotFound        = 402 # An operation was attempted on a file that does not exist.
    ModuleNotFound      = 403 # An operation was attempted on a module that does not exist.
    MemoryNotMapped     = 404 # An operation was attempted on a region of memory that is not mapped in the page table.
    ThreadNotFound      = 405 # An operation was attempted on a thread that does not exist.
    SetSysTimeFailed    = 406 # An attempt to set the system time with the setsystime command failed. This status code is undocumented.
    UnknownCommand      = 407 # The command sent was not recognized.
    ThreadNotStopped    = 408 # The target thread is not stopped.
    FileCopyOnly        = 409 # A move operation was attempted on a file that can only be copied.
    FileAlreadyExists   = 410 # A file could not be created or moved because one already exists with the same name.
    DirNotEmpty         = 411 # A directory could not be deleted because it still contains files and/or directories. (I hate this error so much, it's so anoying, just delete all the things plz, it's fine.)
    FilenameInvalid     = 412 # The specified file contains invalid characters or is too long.
    FileNotCreated      = 413 # The file cannot be created for some unspecified reason.
    AccessDenied        = 414 # The file cannot be accessed at the connection's current privilege level.
    InsufficientSpace   = 415 # The target device has run out of storage space.
    NotDebuggable       = 416 # The title is not debuggable.
    CntTypeInvalid      = 417 # The performance counter type is invalid.
    CntDataUnavailable  = 418 # The performance counter data is not available.
    XboxNotLocked       = 420 # The command can only be executed when security is enabled.
    KeyXchgRequired     = 421 # The client must perform a key exchange with the keyxchg command.
    DediConnRequired    = 422 # The command can only be executed on a dedicated connection.

class DebugMemStatus(Enum):
    # Debug memory status codes
    Undefined = 0
    Enabled   = 1
    Disabled  = 2

class DumpMode(Enum):
    # Dump mode options
    Undefined = 0
    Smart     = 1
    Enabled   = 2
    Disabled  = 3

class DumpReport(Enum):
    # Dump report options
    Undefined = 0
    Prompt    = 1
    Always    = 2
    Never     = 3

class DumpDestination(Enum):
    # Dump destination options
    Local  = 0
    Remote = 1

class DumpFormat(Enum):
    # Dump format options
    FullHeap    = 0
    PartialHeap = 1
    NoHeap      = 2
    Retail      = 3

class DumpSettings:
    # Settings for memory dumps
    def __init__(self):
        self.report = DumpReport.Undefined
        self.destination = DumpDestination.Local
        self.format = DumpFormat.FullHeap
        self.path = ""

class SystemInformation:
    # System information for the Xbox 360
    def __init__(self):
        self.hdd_enabled = False 
        self.type = ""
        self.platform = ""
        self.system = ""
        self.base_kernel_version = ""
        self.kernel_version = ""
        self.recovery_version = "" # same as dmversion?

class Drive:
    # Drive information
    def __init__(self):
        self.name = ""
        self.friendly_name = ""
        self.free_bytes_available = 0
        self.total_bytes = 0
        self.total_free_bytes = 0

class FileEntry:
    # File entry information
    def __init__(self):
        self.name = ""
        self.size = 0
        self.creation_time = 0
        self.modified_time = 0
        self.directory = False

class Module:
    # Module information
    def __init__(self):
        self.name = ""
        self.base_address = 0
        self.size = 0
        self.checksum = 0
        self.timestamp = 0
        self.data_address = 0
        self.data_size = 0
        self.thread_id = 0
        self.original_size = 0
        self.sections = []

class ModuleSection:
    # Module section information
    def __init__(self):
        self.name = ""
        self.base_address = 0
        self.size = 0
        self.index = 0
        self.flags = 0

class Thread:
    # Thread information
    def __init__(self):
        self.id = 0
        self.suspend_count = 0
        self.priority = 0
        self.tls_base_address = 0
        self.base_address = 0
        self.limit = 0
        self.slack = 0
        self.creation_time = 0
        self.name_address = 0
        self.name_length = 0
        self.current_processor = 0
        self.last_error = 0

class MemoryRegion:
    # Memory region information
    def __init__(self):
        self.base_address = 0
        self.size = 0
        self.protection = ""

class GamepadState:
    # Gamepad state information
    def __init__(self):
        self.digital_buttons = 0
        self.lt = 0
        self.rt = 0
        self.lx = 0
        self.ly = 0
        self.rx = 0
        self.ry = 0
        self.reserved1 = 0
        self.reserved2 = 0


class XBDMClient:
    """
    Xbox 360 XBDM Client

    Handles communication with an Xbox 360 devkit via XBDM protocol.
    """
    
    XBDM_PORT = 730
    RECV_TIMEOUT = 5  # seconds

    def __init__(self, console_ip: str):
        # Initialize
        self.ip = console_ip
        self.socket = None
        self.connected = False
        
        # Cache variables
        self.debug_mem_status = DebugMemStatus.Undefined
        self.debug_mem_size = 0xFFFFFFFF
        self.dump_mode = DumpMode.Undefined
        self.dump_settings = DumpSettings()
        self.system_information = SystemInformation()
        self.drives = []
        self.loaded_modules = []
        self.threads = []
        self.memory_regions = []
        self.features = ""
        self.debug_name = ""
        self.active_title = ""
        self.console_type = ""
        self.PID = ""
    
    def open_connection(self) -> bool:
        # Open a connection to the console.
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.RECV_TIMEOUT)
            self.socket.connect((self.ip, self.XBDM_PORT))
            
            # Read initial response
            buffer = self.receive_text_buffer(0x80)
            self.connected = (buffer == "201- connected\r\n")
            return self.connected
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def close_connection(self) -> bool:
        # Close the connection to the console.
        if self.connected:
            try:
                self.send_command("bye")
                self.socket.shutdown(socket.SHUT_WR)
                self.socket.close()
                self.connected = False
                return True
            except Exception as e:
                print(f"Error closing connection: {e}")
                return False
        return True
    
    def reset_connection(self) -> bool:
        # Reset the connection to the console.
        self.close_connection()
        return self.open_connection()
    
    def send_binary(self, buffer: bytes) -> bool:
        # Send binary data to the console.
        try:
            self.socket.sendall(buffer)
            return True
        except Exception as e:
            print(f"Error sending binary data: {e}")
            return False
    
    def receive_binary(self, length: int) -> Tuple[bytes, int]:
        # Receive binary data from the console.
        try:
            data = b''
            bytes_received = 0
            
            while bytes_received < length:
                chunk = self.socket.recv(length - bytes_received)
                if not chunk:
                    break
                data += chunk
                bytes_received += len(chunk)
            
            return data, bytes_received
        except socket.timeout:
            print("Socket timeout while receiving binary data")
            return b'', 0
        except Exception as e:
            print(f"Error receiving binary data: {e}")
            return b'', 0
    
    def receive_text_buffer(self, length: int) -> str:
        # Receive a text buffer from the console.
        try:
            # Peek at the data first
            peek_data = b''
            self.socket.setblocking(True)
            peek_data = self.socket.recv(length, socket.MSG_PEEK)
            
            # Find the end of the message
            len_to_get = 0
            for i in range(len(peek_data)):
                if peek_data[i] == 0:
                    break
                len_to_get += 1
            
            # Now actually read the bytes off the queue
            data = b''
            if len_to_get > 0:
                data = self.socket.recv(len_to_get)
            
            return data.decode('utf-8')
        except Exception as e:
            print(f"Error receiving text buffer: {e}")
            return ""
    
    def send_command(self, command: str, response_length: int = 4096, status_length: int = -1) -> Tuple[str, ResponseStatus]:
        """
        Send a raw command to the Xbox 360 console and return the response.
        
        Args:
            command: The command to send
            response_length: Maximum length of the response buffer
            status_length: Length of the status line to read
            
        Returns:
            Tuple of (response text, status code)
        """
        if not self.connected:
            print("Not connected to console")
            return "", ResponseStatus.Error
        
        # Send the command
        full_command = f"{command}\r\n"
        if not self.send_binary(full_command.encode('utf-8')):
            return "", ResponseStatus.Error
        
        # Give the console time to process the command
        time.sleep(0.02)
        
        # Get the response
        return self.receive_response(response_length, status_length)
    
    def receive_response(self, response_length: int = 4096, status_length: int = -1) -> Tuple[str, ResponseStatus]:
        """
        Receive a response from the Xbox 360 console.
        
        Args:
            response_length: Maximum length of the response buffer
            status_length: Length of the status line to read
            
        Returns:
            Tuple of (response text, status code)
        """
        try:
            # Read the status code (first 3 bytes)
            status_data, _ = self.receive_binary(5)
            if not status_data:
                return "", ResponseStatus.Error
            
            status_str = status_data[:3].decode('utf-8')
            status_int = int(status_str)
            status = ResponseStatus(status_int)
            
            response = ""
            
            # Parse the response based on status code
            if status == ResponseStatus.OK or status == ResponseStatus.ReadyToAcceptData:
                response = self.receive_text_buffer(response_length)
            
            elif status == ResponseStatus.Multiline:
                # Read the "multiline response follows" message
                if status_length == -1:
                    self.receive_binary(0x1C)
                else:
                    self.receive_binary(status_length)
                
                # Read the multiline response until the end marker
                while "\r\n." not in response and ".\r\n" not in response:
                    buffer = self.receive_text_buffer(0x400)
                    if not buffer:
                        break
                    response += buffer
            
            elif status == ResponseStatus.Binary:
                # Read the "binary response follows" message
                if status_length == -1:
                    self.receive_binary(0x19)
                else:
                    self.receive_binary(status_length)
                
                # The caller will need to handle reading the binary stream
                pass
            
            elif status == ResponseStatus.Error:
                response = self.receive_text_buffer(response_length)
            
            # Trim leading and trailing whitespace
            response = response.strip()
            
            return response, status
        
        except Exception as e:
            print(f"Error receiving response: {e}")
            return "", ResponseStatus.Error

    #######################################################################################################################
    # Helper Functions
    #######################################################################################################################
    
    def get_integer_property(self, response: str, property_name: str, hex_format: bool = False) -> int:
        # Extract an integer property from a response string.
        try:
            # Find the property in the response
            start_idx = response.find(property_name)
            if start_idx == -1:
                return 0
            
            # Find the value
            start_idx += len(property_name) + 1  # +1 for the '='
            
            # Find the end of the value
            space_idx = response.find(' ', start_idx)
            cr_idx = response.find('\r', start_idx)
            end_idx = min(space_idx if space_idx != -1 else float('inf'), 
                         cr_idx if cr_idx != -1 else float('inf'))
            
            if end_idx == float('inf'):
                end_idx = len(response)
            
            value_str = response[start_idx:end_idx]
            
            # Convert to integer
            if hex_format:
                return int(value_str, 16)
            else:
                return int(value_str)
        
        except Exception as e:
            print(f"Error getting integer property {property_name}: {e}")
            return 0
    
    def get_string_property(self, response: str, property_name: str) -> str:
        """
        Extract a property value from a response string.
        This function handles both formats:
        - PropertyName="Value" (quoted, and unnecessary? but well add the option just in case.)
        - PropertyName=Value (unquoted)
        """
        try:
            # First try to match quoted format: PropertyName="Value"
            quoted_pattern = r'(?:^|\s)' + re.escape(property_name) + r'="([^"]*)"'
            quoted_match = re.search(quoted_pattern, response)
            
            if quoted_match:
                return quoted_match.group(1)
            
            # If no quoted match, try unquoted format: PropertyName=Value
            unquoted_pattern = r'(?:^|\s)' + re.escape(property_name) + r'=([^\s\r\n]+)'
            unquoted_match = re.search(unquoted_pattern, response)
            
            if unquoted_match:
                return unquoted_match.group(1)
            
            return ""
        
        except Exception as e:
            print(f"Error getting string property {property_name}: {e}")
            return ""
        
    def get_enum_property(self, response: str, property_name: str) -> str:
        # Extract an enum property from a response string.
        try:
            # Search for the property with proper boundaries (space, start of line)
            pattern = r'(?:^|\s)' + re.escape(property_name) + r'='
            match = re.search(pattern, response)
            if not match:
                return ""
            
            # Find the value
            start_idx = match.end()
            
            # Find the end of the value
            space_idx = response.find(' ', start_idx)
            cr_idx = response.find('\r', start_idx)
            nl_idx = response.find('\n', start_idx)
            
            # Use all possible terminators
            end_indices = [i for i in [space_idx, cr_idx, nl_idx] if i != -1]
            end_idx = min(end_indices) if end_indices else len(response)
            
            return response[start_idx:end_idx]
        
        except Exception as e:
            print(f"Error getting enum property {property_name}: {e}")
            return ""

    #######################################################################################################################
    # XBDM Functions
    #######################################################################################################################
    
    def get_memory(self, address: int, length: int) -> bytes:
        """
        Read memory from the Xbox 360 console.
        
        Args:
            address: The memory address to read from
            length: The number of bytes to read
            
        Returns:
            The memory data as bytes
        """
        # Format the command
        command = f"getmemex addr=0x{address:08x} length=0x{length:08x}"
        
        # Send the command
        response, status = self.send_command(command)
        
        if status != ResponseStatus.Binary:
            print(f"Error getting memory: {response}")
            return b''
        
        # Read the memory in chunks
        buffer = bytearray(length)
        offset = 0
        
        while length >= 0x400:
            # Read the flag bytes
            self.receive_binary(2)
            
            # Read the memory chunk
            chunk, bytes_received = self.receive_binary(0x400)
            if bytes_received != 0x400:
                print(f"Error reading memory chunk: expected 0x400 bytes, got {bytes_received}")
                return bytes(buffer[:offset])
            
            buffer[offset:offset+0x400] = chunk
            length -= 0x400
            offset += 0x400
        
        if length > 0:
            # Read the flag bytes
            self.receive_binary(2)
            
            # Read the remaining bytes
            chunk, bytes_received = self.receive_binary(length)
            if bytes_received != length:
                print(f"Error reading memory chunk: expected {length} bytes, got {bytes_received}")
                return bytes(buffer[:offset])
            
            buffer[offset:offset+length] = chunk
        
        return bytes(buffer)
    
    def set_memory(self, address: int, data: bytes) -> bool:
        """
        Write memory to the Xbox 360 console.
        
        Args:
            address: The memory address to write to
            data: The data to write
            
        Returns:
            True if successful, False otherwise
        """
        length = len(data)
        offset = 0
        
        while length > 0:
            # The Xbox can only receive 128 bytes at once
            bytes_to_send = min(length, 128)
            
            # Build the command
            command = f"setmem addr=0x{address + offset:08x} data="
            for i in range(bytes_to_send):
                command += f"{data[offset + i]:02x}"
            
            # Send the command
            response, status = self.send_command(command)
            
            if status != ResponseStatus.OK:
                print(f"Error setting memory: {response}")
                return False
            
            # Update for next iteration
            offset += bytes_to_send
            length -= bytes_to_send
        
        return True
    
    def dump_memory(self, address: int, length: int, dump_path: str) -> bool:
        """
        Dump memory from the Xbox 360 console to a file.
        
        Args:
            address: The memory address to dump from
            length: The number of bytes to dump
            dump_path: The path to save the dump to
            
        Returns:
            True if successful, False otherwise
        """
        # Read the memory from the console
        memory = self.get_memory(address, length)
        
        if not memory:
            return False
        
        # Write the memory to the file
        try:
            with open(dump_path, 'wb') as f:
                f.write(memory)
            return True
        except Exception as e:
            print(f"Error writing memory dump to file: {e}")
            return False
    
    def get_screenshot(self) -> bytes:
        """
        Get a screenshot from the Xbox 360 console.
        
        Returns:
            The screenshot data as bytes
        """
        # Send the command
        response, status = self.send_command("screenshot")
        
        if status != ResponseStatus.Binary:
            print(f"Error getting screenshot: {response}")
            return b''
        
        # Get the screenshot size
        size = self.get_integer_property(response, "framebuffersize", True)
        
        if size == 0:
            print("Error getting screenshot size")
            return b''
        
        # Get the screenshot data
        screenshot_data, bytes_received = self.receive_binary(size)
        
        if bytes_received != size:
            print(f"Error receiving screenshot: expected {size} bytes, got {bytes_received}")
            return b''
        
        return screenshot_data
    
    def get_debug_memory_size(self) -> int:
        """
        Get the size of the debug memory.
        
        Returns:
            The size of the debug memory
        """
        if self.debug_mem_size == 0xFFFFFFFF:
            response, status = self.send_command("debugmemsize")
            
            if status == ResponseStatus.OK:
                self.debug_mem_size = self.get_integer_property(response, "debugmemsize", True)
        
        return self.debug_mem_size
    
    def get_debug_memory_status(self) -> DebugMemStatus:
        """
        Get the status of the debug memory.
        
        Returns:
            The debug memory status
        """
        if self.debug_mem_status == DebugMemStatus.Undefined:
            response, status = self.send_command("consolemem")
            
            if status == ResponseStatus.OK:
                mem_status = self.get_integer_property(response, "consolemem", True)
                self.debug_mem_status = DebugMemStatus(mem_status)
        
        return self.debug_mem_status
    
    def get_dump_mode(self) -> DumpMode:
        """
        Get the dump mode.
        
        Returns:
            The dump mode
        """
        if self.dump_mode == DumpMode.Undefined:
            response, status = self.send_command("dumpmode")
            
            if status == ResponseStatus.OK:
                if response == "smart":
                    self.dump_mode = DumpMode.Smart
                elif response == "enabled":
                    self.dump_mode = DumpMode.Enabled
                elif response == "disabled":
                    self.dump_mode = DumpMode.Disabled
        
        return self.dump_mode
    
    def get_system_information(self) -> SystemInformation:
        """
        Get system information from the Xbox 360 console.
        
        Returns:
            The system information
        """
        if not self.system_information.platform:
            response, status = self.send_command("systeminfo")
            
            if status == ResponseStatus.Multiline:
                info = SystemInformation()
                info.hdd_enabled = self.get_enum_property(response, "HDD") == "Enabled"
                info.type = self.get_enum_property(response, "Type")
                info.platform = self.get_enum_property(response, "Platform")
                info.system = self.get_enum_property(response, "System")
                info.base_kernel_version = self.get_enum_property(response, "BaseKrnl")
                info.kernel_version = self.get_enum_property(response, "Krnl")
                info.recovery_version = self.get_enum_property(response, "XDK")
                
                self.system_information = info
        
        return self.system_information

    def get_system_type(self) -> str:
        '''
        The type info from systeminfo appears to be either wrong or spoofed
        This info is still incorrect, but it's better
        '''
        response, status = self.send_command('consoletype')
        
        if status != ResponseStatus.OK:
            return ""
        return response
    
    def get_drives(self) -> List[Drive]:
        """
        Get a list of drives from the Xbox 360 console.
        
        Returns:
            A list of drives
        """
        if not self.drives:
            response, status = self.send_command("drivelist")
            
            if status == ResponseStatus.Multiline:
                drives = []
                parts = response.split("drivename=")
                
                # Skip the first part (empty or header)
                for part in parts[1:]:
                    drive = Drive()
                    drive.name = part.split('"')[1]
                    drives.append(drive)
                
                # Get drive size information
                for drive in drives:
                    resp, stat = self.send_command(f'drivefreespace name="{drive.name}:\\\"')
                    
                    if stat == ResponseStatus.Multiline:
                        free_hi = self.get_integer_property(resp, "freetocallerhi", True)
                        free_lo = self.get_integer_property(resp, "freetocallerlo", True)
                        total_hi = self.get_integer_property(resp, "totalbyteshi", True)
                        total_lo = self.get_integer_property(resp, "totalbyteslo", True)
                        free_bytes_hi = self.get_integer_property(resp, "totalfreebyteshi", True)
                        free_bytes_lo = self.get_integer_property(resp, "totalfreebyteslo", True)
                        
                        drive.free_bytes_available = (free_hi << 32) | free_lo
                        drive.total_bytes = (total_hi << 32) | total_lo
                        drive.total_free_bytes = (free_bytes_hi << 32) | free_bytes_lo
                        
                        # Set friendly name
                        if drive.name in ["DEVKIT", "E"]:
                            drive.friendly_name = f"Game Development Volume ({drive.name})"
                        elif drive.name == "HDD":
                            drive.friendly_name = f"Retail Hard Drive Emulation ({drive.name})"
                        elif drive.name == "Y":
                            drive.friendly_name = f"Xbox360 Dashboard Volume ({drive.name})"
                        elif drive.name == "Z":
                            drive.friendly_name = f"Devkit Drive ({drive.name})"
                        else:
                            drive.friendly_name = f"Volume ({drive.name})"
                
                self.drives = drives
        
        return self.drives
    
    def get_directory_contents(self, directory: str) -> List[FileEntry]:
        """
        Get a list of files and directories from a directory on the Xbox 360 console.
        
        Args:
            directory: The directory to list
            
        Returns:
            A list of file entries
        """
        response, status = self.send_command(f'dirlist name="{directory}"')
        
        if status != ResponseStatus.OK or response.startswith("file not found"):
            return []
        
        entries = []
        lines = response.split("\r\n")
        
        for line in lines:
            if not line:
                continue
            
            entry = FileEntry()
            
            # Try to extract the basic properties
            name_match = line.find('name="')
            if name_match != -1:
                name_start = name_match + 6
                name_end = line.find('"', name_start)
                entry.name = line[name_start:name_end]
            
            # Check if it's a directory
            entry.directory = " directory" in line
            
            # Extract size
            size_hi = 0
            size_lo = 0
            size_hi_match = line.find('sizehi=')
            if size_hi_match != -1:
                size_hi_str = line[size_hi_match+7:].split(' ')[0]
                try:
                    size_hi = int(size_hi_str, 16)
                except ValueError:
                    pass
            
            size_lo_match = line.find('sizelo=')
            if size_lo_match != -1:
                size_lo_str = line[size_lo_match+7:].split(' ')[0]
                try:
                    size_lo = int(size_lo_str, 16)
                except ValueError:
                    pass
            
            entry.size = (size_hi << 32) | size_lo
            
            # Extract timestamps
            create_hi = 0
            create_lo = 0
            create_hi_match = line.find('createhi=')
            if create_hi_match != -1:
                create_hi_str = line[create_hi_match+9:].split(' ')[0]
                try:
                    create_hi = int(create_hi_str, 16)
                except ValueError:
                    pass
            
            create_lo_match = line.find('createlo=')
            if create_lo_match != -1:
                create_lo_str = line[create_lo_match+9:].split(' ')[0]
                try:
                    create_lo = int(create_lo_str, 16)
                except ValueError:
                    pass
            
            entry.creation_time = (create_hi << 32) | create_lo
            
            change_hi = 0
            change_lo = 0
            change_hi_match = line.find('changehi=')
            if change_hi_match != -1:
                change_hi_str = line[change_hi_match+9:].split(' ')[0]
                try:
                    change_hi = int(change_hi_str, 16)
                except ValueError:
                    pass
            
            change_lo_match = line.find('changelo=')
            if change_lo_match != -1:
                change_lo_str = line[change_lo_match+9:].split(' ')[0]
                try:
                    change_lo = int(change_lo_str, 16)
                except ValueError:
                    pass
            
            entry.modified_time = (change_hi << 32) | change_lo
            
            entries.append(entry)
        
        return entries
    
    def receive_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download a file from the Xbox 360 console.
        
        Args:
            remote_path: The path to the file on the Xbox 360
            local_path: The path to save the file to
            
        Returns:
            True if successful, False otherwise
        """
        # Send the command to get the file
        response, status = self.send_command(f'getfile name="{remote_path}"', 0x1E)
        
        if status != ResponseStatus.Binary:
            print(f"Error getting file: {response}")
            return False
        
        # Read the file length (4 bytes)
        length_bytes, bytes_received = self.receive_binary(4)
        
        if bytes_received != 4:
            print("Error reading file length")
            return False
        
        # Convert to little endian
        file_length = struct.unpack("<I", length_bytes)[0]
        
        # Create the local file
        try:
            with open(local_path, 'wb') as outfile:
                # Read the file in chunks
                remaining = file_length
                while remaining > 0:
                    chunk_size = min(remaining, 0x10000)
                    chunk, bytes_received = self.receive_binary(chunk_size)
                    
                    if bytes_received != chunk_size:
                        print(f"Error reading file chunk: expected {chunk_size} bytes, got {bytes_received}")
                        return False
                    
                    outfile.write(chunk)
                    remaining -= bytes_received
            
            return True
        except Exception as e:
            print(f"Error writing file: {e}")
            return False
    
    def send_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a file to the Xbox 360 console.
        
        Args:
            local_path: The path to the local file
            remote_path: The path to save the file on the Xbox 360
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get the file size
            #file_size = os.path.getsize(local_path)
            # Open the file, seek to the end and get the position we seeked to, which is the file size in bytes.
            # as we have seeked over that many bytes to get here.
            with open(local_path, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
            
            # Send the command to start the upload
            command = f'sendfile name="{remote_path}" length=0x{file_size:x}'
            response, status = self.send_command(command)
            
            if status != ResponseStatus.ReadyToAcceptData:
                print(f"Error starting file upload: {response}")
                return False
            
            # Send the file in chunks
            with open(local_path, 'rb') as infile:
                while True:
                    chunk = infile.read(0x10000)
                    if not chunk:
                        break
                    
                    if not self.send_binary(chunk):
                        print("Error sending file chunk")
                        return False
            
            return True
        except Exception as e:
            print(f"Error sending file: {e}")
            return False
    
    def delete_file(self, path: str) -> bool:
        """
        Delete a file on the Xbox 360 console.
        
        Args:
            path: The path to the file to delete
            
        Returns:
            True if successful, False otherwise
        """
        response, status = self.send_command(f'delete name="{path}"')
        
        if status != ResponseStatus.OK:
            print(f"Error deleting file: {response}")
            return False
        
        return True
    
    def create_directory(self, path: str) -> bool:
        """
        Create a directory on the Xbox 360 console.
        
        Args:
            path: The path to the directory to create
            
        Returns:
            True if successful, False otherwise
        """
        response, status = self.send_command(f'mkdir name="{path}"')
        
        if status != ResponseStatus.OK:
            print(f"Error creating directory: {response}")
            return False
        
        return True
    
    def delete_directory(self, path: str, recursive: bool = False) -> bool:
        """
        Delete a directory on the Xbox 360 console.
        
        Args:
            path: The path to the directory to delete
            recursive: Whether to delete recursively
            
        Returns:
            True if successful, False otherwise
        """
        if recursive:
            # Get directory contents
            entries = self.get_directory_contents(path)
            
            # Delete all files and subdirectories
            for entry in entries:
                full_path = f"{path}\\{entry.name}"
                if entry.directory:
                    if not self.delete_directory(full_path, True):
                        return False
                else:
                    if not self.delete_file(full_path):
                        return False
        
        # Delete the directory itself
        response, status = self.send_command(f'rmdir name="{path}"')
        
        if status != ResponseStatus.OK:
            print(f"Error deleting directory: {response}")
            return False
        
        return True
    
    def get_loaded_modules(self) -> List[Module]:
        """
        Get a list of loaded modules from the Xbox 360 console.
        
        Returns:
            A list of modules
        """
        if not self.loaded_modules:
            response, status = self.send_command("modules")
            
            if status == ResponseStatus.Multiline:
                modules = []
                lines = response.split("\r\n")
                
                for line in lines:
                    if not line or line == ".":
                        continue
                    
                    module = Module()
                    parts = line.split()
                    
                    # Parse all the module information
                    for part in parts:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            
                            if key == "name":
                                module.name = value.strip('"')
                            elif key == "base":
                                module.base_address = int(value, 16)
                            elif key == "size":
                                module.size = int(value, 16)
                            elif key == "check":
                                module.checksum = int(value, 16)
                            elif key == "timestamp":
                                module.timestamp = int(value, 16)
                            elif key == "dataaddr":
                                module.data_address = int(value, 16)
                            elif key == "datasize":
                                module.data_size = int(value, 16)
                            elif key == "threadid":
                                module.thread_id = int(value, 16)
                            elif key == "origsize":
                                module.original_size = int(value, 16)
                    
                    if module.name:
                        modules.append(module)
                
                self.loaded_modules = modules
        
        return self.loaded_modules
    
    def get_threads(self) -> List[Thread]:
        """
        Get a list of threads from the Xbox 360 console.
        
        Returns:
            A list of threads
        """
        if not self.threads:
            response, status = self.send_command("threads")
            
            if status == ResponseStatus.Multiline:
                threads = []
                lines = response.split("\r\n")
                
                for line in lines:
                    if not line or line == ".":
                        continue
                    
                    thread = Thread()
                    parts = line.split()
                    
                    # Parse all the thread information
                    for part in parts:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            
                            if key == "id":
                                thread.id = int(value, 16)
                            elif key == "suspend":
                                thread.suspend_count = int(value, 16)
                            elif key == "priority":
                                thread.priority = int(value, 16)
                            elif key == "tlsbase":
                                thread.tls_base_address = int(value, 16)
                            elif key == "base":
                                thread.base_address = int(value, 16)
                            elif key == "limit":
                                thread.limit = int(value, 16)
                            elif key == "slack":
                                thread.slack = int(value, 16)
                            elif key == "create":
                                thread.creation_time = int(value, 16)
                            elif key == "nameaddr":
                                thread.name_address = int(value, 16)
                            elif key == "namelen":
                                thread.name_length = int(value, 16)
                            elif key == "curproc":
                                thread.current_processor = int(value, 16)
                            elif key == "lasterror":
                                thread.last_error = int(value, 16)
                    
                    if thread.id:
                        threads.append(thread)
                
                self.threads = threads
        
        return self.threads
    
    def get_memory_regions(self) -> List[MemoryRegion]:
        """
        Get a list of memory regions from the Xbox 360 console.
        
        Returns:
            A list of memory regions
        """
        if not self.memory_regions:
            response, status = self.send_command("memregions")

            if status == ResponseStatus.Multiline:
                regions = []
                lines = response.split("\r\n")
                
                for line in lines:
                    if not line or line == ".":
                        continue
                    
                    region = MemoryRegion()
                    parts = line.split()
                    
                    # Parse all the memory region information
                    for part in parts:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            
                            if key == "addr":
                                region.base_address = int(value, 16)
                            elif key == "size":
                                region.size = int(value, 16)
                            elif key == "protect":
                                region.protection = value
                    
                    if region.base_address and region.size:
                        regions.append(region)
                
                self.memory_regions = regions
        
        return self.memory_regions
    
    def get_features(self) -> str:
        """
        Get a list of features supported by the Xbox 360 console.
        
        Returns:
            A string containing the features
        """
        if not self.features:
            response, status = self.send_command("featurelist")
            
            if status == ResponseStatus.OK:
                self.features = response
        
        return self.features
    
    def get_debug_name(self) -> str:
        """
        Get the debug name of the Xbox 360 console.
        
        Returns:
            The debug name
        """
        if not self.debug_name:
            response, status = self.send_command("dbgname")
            if status == ResponseStatus.OK:
                self.debug_name = response
        
        return self.debug_name
    
    def set_debug_name(self, name: str) -> bool:
        """
        Set the debug name of the Xbox 360 console.
        
        Args:
            name: The debug name to set
            
        Returns:
            True if successful, False otherwise
        """
        response, status = self.send_command(f'dbgname name="{name}"')
        
        if status == ResponseStatus.OK:
            self.debug_name = name
            return True
        
        return False
    
    def get_active_title(self) -> str:
        """
        Get the path of active title on the Xbox 360 console.
        
        Returns:
            The active title path
        """
        if not self.active_title:
            response, status = self.send_command("xbeinfo running")
            print(response)
            
            if status == ResponseStatus.Multiline:
                self.active_title = self.get_string_property(response, "name")
        
        return self.active_title
    
    def get_console_type(self) -> str:
        """
        Get the console type of the Xbox 360 console.
        
        Returns:
            The console type
        """
        if not self.console_type:
            response, status = self.send_command("consolefeatures")
            
            if status == ResponseStatus.OK:
                self.console_type = response
        
        return self.console_type
    
    def get_gamepad_state(self, port: int = 0) -> GamepadState:
        """
        Get the state of a gamepad connected to the Xbox 360 console.
        
        Args:
            port: The port number (0-3)
            
        Returns:
            The gamepad state
        """
        if port < 0 or port > 3:
            print("Invalid gamepad port (must be 0-3)")
            return GamepadState()
        
        response, status = self.send_command(f"getgpdstate port={port}")
        
        if status != ResponseStatus.OK:
            return GamepadState()
        
        state = GamepadState()
        
        # Parse the gamepad state
        state.digital_buttons = self.get_integer_property(response, "dwButtons", True)
        state.lt = self.get_integer_property(response, "bLeftTrigger", True)
        state.rt = self.get_integer_property(response, "bRightTrigger", True)
        state.lx = self.get_integer_property(response, "sThumbLX", True)
        state.ly = self.get_integer_property(response, "sThumbLY", True)
        state.rx = self.get_integer_property(response, "sThumbRX", True)
        state.ry = self.get_integer_property(response, "sThumbRY", True)
        
        return state
    
    def launch_title(self, title_path: str) -> bool:
        """
        Launch a title on the Xbox 360 console.
        
        Args:
            title_path: The path to the title to launch
            
        Returns:
            True if successful, False otherwise

        TODO:
            Add debug flag so XBDM will remain loaded while the title is running. 
        """
        response, status = self.send_command(f'magicboot title="{title_path}"')
        
        if status != ResponseStatus.OK:
            print(f"Error launching title: {response}")
            return False
        
        return True
    
    def reboot_console(self) -> bool:
        """
        Reboot the Xbox 360 console.
        
        Returns:
            True if successful, False otherwise
        """
        response, status = self.send_command("magicboot")
        
        if status != ResponseStatus.OK:
            print(f"Error rebooting console: {response}")
            return False
        
        # Reset the connection after rebooting
        # This only works on JTAG or RGH
        self.close_connection()
        
        # Give the console time to reboot
        time.sleep(5)
        
        return self.open_connection()

    def cold_reboot_console(self) -> bool:
        '''
        Hard Reboots the xbox. This appears to be undocumented.
        Warning: If you are running BadUpdate you will lose your explit.
        '''
        response, status = self.send_command("magicboot  COLD")

        if status != ResponseStatus.OK:
            print(f"Error rebooting console: {response}")
            return False


        # Reset the connection after rebooting
        # This only works on JTAG or RGH
        self.close_connection()
        
        # Give the console time to reboot
        time.sleep(5)
        
        return self.open_connection()

    
    def stop_title(self) -> bool:
        """
        Stop the currently running title on the Xbox 360 console.
        
        Returns:
            True if successful, False otherwise
        """
        response, status = self.send_command("stop")
        
        if status != ResponseStatus.OK:
            print(f"Error stopping title: {response}")
            return False
        
        return True
    
    def go(self) -> bool:
        """
        Resume execution of the currently running title on the Xbox 360 console.
        
        Returns:
            True if successful, False otherwise
        """
        response, status = self.send_command("go")
        
        if status != ResponseStatus.OK:
            print(f"Error resuming execution: {response}")
            return False
        
        return True

    def get_pid(self) -> str:
        '''
        Undocumented?
        Gets the currently running process ID

        Returns:
            string of the 0x hex
        '''
        response, status = self.send_command("getpid")
        if status == ResponseStatus.OK:
            print(response)
            self.PID = self.get_string_property(response, "pid")

        return self.PID

    def get_dmv(self) -> str:
        '''
        Get the version string of the debug monitor running on the console

        Retruns:
            String like 2.0.21076.11
        '''
        response, status = self.send_command("dmversion")
        if status == ResponseStatus.OK:
            return response

    #####################################################################################
    # JRPC Functions
    # Functions ported from JRPC, but unsure yet if we need JRPC running for them to work
    # Msg Type checklist:
    # 0~8: Unknown
    # 9: Kinda ported
    # 10,11,12: Ported
    # 13: Redundant (get_system_information())
    # 14: Half ported (It works, but I need to know why it works)
    # 15: Ported, but has bugs?
    # 16: Ported
    # 17: Redundant (get_system_information())
    # 18: ??? (its constantMemorySetting but idk what that is or does)
    #
    # Missing:
    # We are still missing all the special call functions. for eg.
    # public static T Call<T>(this IXboxConsole console, uint Address, params object[] Arguments) where T : struct
    # public static void CallVoid(this IXboxConsole console, uint Address, params object[] Arguments)
    # public static T[] CallArray<T>(this IXboxConsole console, ThreadType Type, string module, int ordinal, uint ArraySize, params object[] Arguments) where T : struct
    # I just haven't fully decoded how they work yet or how to do them in python.
    #####################################################################################

    def resolve_function(self, moduleName, ordinal) -> str:
        '''
        Sorry, idk what this does. It has something to do with freeing memory for or from
        plugins. sounds kinda spoopie.

        Usage
            pAddress = xbdm.resolve_function("xam.xex", 2601) + 0x3000;
        '''
        module_len = len(moduleName)
        module_hex = ''.join(format(ord(c), 'x') for c in moduleName)
        response, status = self.send_command(f"consolefeatures ver=2 type=9 params=\"A\\0\\A\\2\\2/{module_len}\\{module_hex}\\1\\{ordinal}\\\"")
        #if status == ResponseStatus.OK:

    def get_cpukey(self) -> str:
        '''
        Gets the CPU Key from your console. Used to decrypt your nand and key vault
        '''
        response, status = self.send_command("consolefeatures ver=2 type=10 params=\"A\\0\\A\\0\\\"")
        if status == ResponseStatus.OK:
            return response

    def send_shutdown(self):
        '''
        Hard power off the console
        This code is semi redundant, magiboot does have reboot and launch options, it should have a shutdown option too
        but it's all undocumented so idk..

        This function does not return anything, as well, the xbox is off now. The dead don't speek.
        '''
        command = "consolefeatures ver=2 type=11 params=params=\"A\\0\\A\\0\\\""
        self.send_command(command)

    def x_notify(self, type, message) -> bool:
        '''
        Sends a notification to the Xbox 360
        (I'm not 100% if this is solely done in XBDM or if we are using JRPC)
        This function will count the length of your message, convert it to hex
        then send the length of the message and the message in hex to the console.
        You can also send custom message types like new friend requests and achievements.
        Please Note: This function isn't 100% implemented yet.
        We are not pushing this notify with all available parameters
        So we cant set custom timers or custom achievement points yet.

        Usage:
            xbdm.x_notify("NULLED", "Hello World")
            xbdm.x_notify("FRIEND_REQUEST_LOGO", "MobCat wants to be your friend")

        Returns:
            True If message response is OK
            BUG: This may be a bug as sending an invalid message type still returns ok.
        '''
        # I don't think this should go here but okie
        # Please see this gist for more info on xnotify types
        # https://gist.github.com/MobCat/bca5af6436a312b3445e9d6f38a38ea3
        # Any message type that does  not work on 2.0.17559.0 has been removed.
        MessageTypes = {
            'NULLED':                                        0,
            'NEW_MESSAGE_LOGO':                              1,
            'FRIEND_REQUEST_LOGO':                           2,
            'NEW_MESSAGE':                                   3,
            'GAMERTAG_SENT_YOU_A_MESSAGE':                   5,
            'GAMERTAG_SINGED_OUT':                           6,
            'GAMERTAG_SIGNED_IN':                            7,
            'GAMERTAG_SIGNED_INTO_XBOX_LIVE':                8,
            'GAMERTAG_SIGNED_IN_OFFLINE':                    9,
            'GAMERTAG_WANTS_TO_CHAT':                        10,
            'DISCONNECTED_FROM_XBOX_LIVE':                   11,
            'DOWNLOADED':                                    12,
            'FLASHING_MUSIC_SYMBOL':                         13,
            'FLASHING_HAPPY_FACE':                           14,
            'FLASHING_FROWNING_FACE':                        15,
            'FLASHING_DOUBLE_SIDED_HAMMER':                  16,
            'GAMERTAG_WANTS_TO_CHAT_2':                      17,
            'PLEASE_REINSERT_MEMORY_UNIT':                   18,
            'PLEASE_RECONNECT_CONTROLLER':                   19,
            'GAMERTAG_HAS_JOINED_CHAT':                      20,
            'GAMERTAG_HAS_LEFT_CHAT':                        21,
            'GAME_INVITE_SENT':                              22,
            'PAGE_SENT_TO':                                  24,
            'ACHIEVEMENT_UNLOCKED':                          27,
            'GAMERTAG_WANTS_TO_TALK_IN_VIDEO_KINECT':        29,
            'READY_TO_PLAY':                                 31,
            'CANT_DOWNLOAD_X':                               32,
            'DOWNLOAD_STOPPED_FOR_X':                        33,
            'FLASHING_XBOX_CONSOLE':                         34,
            'X_SENT_YOU_A_GAME_MESSAGE':                     35,
            'DEVICE_FULL':                                   36,
            'ACHIEVEMENTS_UNLOCKED':                         39,
            'FAMILY_TIMER_X_TIME_REMAINING':                 45,
            'DISCONNECTED_XBOX_LIVE_11_MINUTES_REMAINING':   46,
            'KINECT_HEALTH_EFFECTS':                         47,
            'GAMERTAG_WANTS_YOU_TO_JOIN_AN_XBOX_LIVE_PARTY': 49,
            'PARTY_INVITE_SENT':                             50,
            'GAME_INVITE_SENT_TO_XBOX_LIVE_PARTY':           51,
            'KICKED_FROM_XBOX_LIVE_PARTY':                   52,
            'DISCONNECTED_XBOX_LIVE_PARTY':                  53,
            'DOWNLOADED':                                    55,
            'CANT_CONNECT_XBL_PARTY':                        56,
            'GAMERTAG_HAS_JOINED_XBL_PARTY':                 57,
            'GAMERTAG_HAS_LEFT_XBL_PARTY':                   58,
            'GAMER_PICTURE_UNLOCKED':                        59,
            'AVATAR_AWARD_UNLOCKED':                         60,
            'JOINED_XBL_PARTY':                              61,
            'PLEASE_REINSERT_USB_STORAGE_DEVICE':            62,
            'PLAYER_MUTED':                                  63,
            'PLAYER_UNMUTED':                                64,
            'KINECT_SENSOR_DETECTED':                        66,
            'FEELING_TIRED':                                 67,
            'KINECT_RECOGNIZED':                             69,
            'SHUTDOWN_SOON':                                 70,
            'XBOX_LIVE_PROFILE_ELSEWHERE':                   71,
            'LAST_SIGNED_IN':                                73,
            'KINECT_NOT_SUPPORTED':                          74,
            'WIRELESS_CONFLICT':                             75,
            'UPDATING':                                      76,
            'SMARTGLASS':                                    77
        }
        try:
            setType = MessageTypes[type]
        except KeyError:
            setType = 0 # Set default of NULLED if no or invalid type is set.

        message_length = len(message)
        message_hex = ''.join(format(ord(c), 'x') for c in message)
        command = f"consolefeatures ver=2 type=12 params=\"A\\0\\A\\2\\2/{message_length}\\{message_hex}\\1\\{setType}\\\""
        response, status = self.send_command(command)
        if status == ResponseStatus.OK:
            return True
        else:
            return False

    def set_LEDs(self, Top_Left, Top_Right, Bottom_Left, Bottom_Right):
        '''
            Set a custom led stat for the xbox front panel LEDS
            This function is still WiP and needs more testing so its
            setup right now to accept any raw hex for a value.
            We will lock this down to RED, GREEN, ORANGE when we confirm a few things.
            
            Usage
                # Turn all leds off
                xbdm.set_LEDs(0x00, 0x00, 0x00, 0x00)
                
                # Set all leds green
                xbdm.set_LEDs(0x80, 0x80, 0x80, 0x80)
                
                # Set all leds to red
                xbdm.set_LEDs(0x08, 0x08, 0x08, 0x08)
                
                # Set all leds to orange (aka red and green at the same time)
                xbdm.set_LEDs(0x88, 0x88, 0x88, 0x88)
                
                # Sets player 1 to red
                xbdm.set_LEDs(0x08, 0x00, 0x00, 0x00)
                
            TODO: 
                We need more testing on slim consoles
                There is a way on those consoles to set the center power LED.
                But the command is unknow or unsupported in JRPC.
                I think there is always a way to set brightness to get fade affects
                like the default boot light affects. but that is also unknown.
        '''
        command = (
            f"consolefeatures ver=2 type=14 params=\"A\\0\\A\\4\\"
            f"1\\{Top_Left}\\"
            f"1\\{Top_Right}\\"
            f"1\\{Bottom_Left}\\"
            f"1\\{Bottom_Right}\\\""
        )

        # We don't get or there isn't a response from JRPC
        # We just shoot and pray
        self.send_command(command)


    def get_Temp(self, type) -> int:
        '''
            Gets temperature from the console in c

            Returns: an int of the temp in c
            Usage:
                xbdm.get_Temp("CPU") # Processor
                xbdm.get_Temp("GPU") # Graphics
                xbdm.get_Temp("MEM") # Memory
                xbdm.get_Temp("CHS") # Chassis
            Bugs:
                The returned value from the console is an int, not a float.
                The returned value for GPU is the same as CPU, even know they are different in auroa
        '''
        IntTypes = {
            'CPU': 0,
            'GPU': 1, #BUGBUG: When asking for GPU temp, we get CPU temp
            'MEM': 2,
            'CHS': 3 # Chassis / shell.
        }
        try:
            setType = IntTypes[type]
        except KeyError:
            setType = 0 # Set default if no or invalid type is set.

        response, status = self.send_command(f"consolefeatures ver=2 type=15 params=\"A\\0\\A\\1\\1\\{setType}\\\"")
        if status == ResponseStatus.OK:
            return int(response[response.find(" ") + 1:], 16) # Decode hex to int
        else:
            return 0

    def get_TitleID(self) -> str:
        '''
            Returns a string of the title ID of the currently running title
            TODO: Find out how to get TU as well.
        '''
        response, status = self.send_command("consolefeatures ver=2 type=16 params=\"A\\0\\A\\0\\\"")
        if status == ResponseStatus.OK:
            return response

    # Test boiler plate function for testing JRPC functions.
    def test(self):
        response, status = self.send_command("consolefeatures ver=2 type=17 params=\"A\\0\\A\\0\\\"")
        print(status)
        print(response)
        
    #TODO:
    #threadinfo thread=72
    # We can get info about specific threads and what they are doing?

########################################################################################

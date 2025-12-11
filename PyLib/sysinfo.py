#!/usr/bin/env python3
# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13

"""
System information gathering script
"""

import os
import sys
import platform
import socket

try:
    info = []
    
    # Basic system information
    info.append(f"System: {platform.system()}")
    info.append(f"Node Name: {platform.node()}")
    info.append(f"Release: {platform.release()}")
    info.append(f"Version: {platform.version()}")
    info.append(f"Machine: {platform.machine()}")
    info.append(f"Processor: {platform.processor()}")
    info.append(f"Python Version: {platform.python_version()}")
    
    # Network information
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        info.append(f"Hostname: {hostname}")
        info.append(f"Local IP: {local_ip}")
    except:
        info.append("Network info: Unable to retrieve")
    
    # User information
    try:
        if hasattr(os, 'getlogin'):
            info.append(f"Current User: {os.getlogin()}")
        else:
            info.append(f"Current User: {os.environ.get('USER', 'Unknown')}")
    except:
        info.append("Current User: Unable to retrieve")
    
    # Current working directory
    info.append(f"Current Directory: {os.getcwd()}")
    
    # Environment variables (limited)
    important_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'TERM']
    for var in important_vars:
        value = os.environ.get(var, 'Not set')
        if len(value) > 100:  # Truncate long values
            value = value[:100] + "..."
        info.append(f"{var}: {value}")
    
    print('\n'.join(info))
    
except Exception as e:
    print(f"Error gathering system information: {e}")
#!/usr/bin/env python3
# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13

"""
Sample PyLib script for path discovery
This is a simplified version for demonstration purposes
"""

import os
import sys

try:
    current_path = os.getcwd()
    files_and_dirs = []
    
    try:
        for item in os.listdir(current_path):
            item_path = os.path.join(current_path, item)
            if os.path.isdir(item_path):
                files_and_dirs.append(item + '/')
            else:
                files_and_dirs.append(item)
    except PermissionError:
        files_and_dirs = ['Permission denied']
    
    # Send the file list
    print('\n'.join(files_and_dirs))
    
    # Send the current path as prompt
    if sys.platform.startswith('win'):
        prompt = f"{current_path}> "
    else:
        prompt = f"{current_path}$ "
    
    print(prompt)
    
except Exception as e:
    print(f"Error: {e}")
    print("C:\\> " if sys.platform.startswith('win') else "/$ ")
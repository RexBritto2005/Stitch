"""
Core communication library for Snitch application.
"""
from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
from typing import Any, Optional

from .Snitch_utils import crypto

logger = logging.getLogger(__name__)


class SnitchConnection:
    """Handles individual client connections."""
    
    def __init__(self, sock: socket.socket, address: tuple[str, int]):
        self.socket = sock
        self.address = address
        self.connected = True
        self.last_seen = time.time()
        self.lock = threading.Lock()
    
    def send_encrypted(self, data: str | dict | bytes) -> bool:
        """Send encrypted data to client."""
        try:
            # Convert data to bytes
            if isinstance(data, dict):
                data = json.dumps(data)
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Encrypt data
            encrypted_data = crypto.encrypt_data(data)
            
            # Send length-prefixed message
            message_length = len(encrypted_data)
            length_header = struct.pack('!I', message_length)
            
            with self.lock:
                self.socket.sendall(length_header + encrypted_data)
            
            self.last_seen = time.time()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send data to {self.address}: {e}")
            self.connected = False
            return False
    
    def receive_encrypted(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive encrypted data from client."""
        try:
            if timeout:
                self.socket.settimeout(timeout)
            
            # Receive message length
            length_data = self._receive_exact(4)
            if not length_data:
                return None
            
            message_length = struct.unpack('!I', length_data)[0]
            
            # Validate message length
            if message_length > 10 * 1024 * 1024:  # 10MB limit
                logger.warning(f"Message too large: {message_length} bytes")
                return None
            
            # Receive encrypted message
            encrypted_data = self._receive_exact(message_length)
            if not encrypted_data:
                return None
            
            # Decrypt data
            decrypted_data = crypto.decrypt_data(encrypted_data)
            
            self.last_seen = time.time()
            return decrypted_data
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Failed to receive data from {self.address}: {e}")
            self.connected = False
            return None
        finally:
            if timeout:
                self.socket.settimeout(None)
    
    def _receive_exact(self, length: int) -> Optional[bytes]:
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
    
    def close(self) -> None:
        """Close the connection."""
        try:
            self.connected = False
            self.socket.close()
        except Exception:
            pass


class SnitchServer:
    """Main server for handling client connections."""
    
    def __init__(self):
        self.connections: dict[str, SnitchConnection] = {}
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.port = 0
        self.lock = threading.Lock()
    
    def start_server(self, port: int) -> bool:
        """Start the server on specified port."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(50)
            
            self.running = True
            self.port = port
            
            # Start accepting connections in background
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            
            logger.info(f"Server started on port {port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return False
    
    def _accept_connections(self) -> None:
        """Accept incoming connections."""
        while self.running and self.server_socket:
            try:
                client_socket, address = self.server_socket.accept()
                client_ip = address[0]
                
                logger.info(f"New connection from {client_ip}:{address[1]}")
                
                # Create connection object
                connection = SnitchConnection(client_socket, address)
                
                with self.lock:
                    self.connections[client_ip] = connection
                
                # Start handling client in background
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(connection,),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, connection: SnitchConnection) -> None:
        """Handle individual client connection."""
        client_ip = connection.address[0]
        
        try:
            # Send initial handshake
            handshake = {
                "type": "handshake",
                "server": "Snitch Python 3.13",
                "timestamp": time.time()
            }
            
            if not connection.send_encrypted(handshake):
                return
            
            # Wait for client response
            response = connection.receive_encrypted(timeout=30.0)
            if response:
                try:
                    client_info = json.loads(response.decode('utf-8'))
                    logger.info(f"Client {client_ip} info: {client_info}")
                except Exception:
                    logger.warning(f"Invalid handshake response from {client_ip}")
            
            # Keep connection alive
            while connection.connected:
                # Send keepalive every 30 seconds
                keepalive = {"type": "keepalive", "timestamp": time.time()}
                if not connection.send_encrypted(keepalive):
                    break
                
                time.sleep(30)
                
        except Exception as e:
            logger.error(f"Error handling client {client_ip}: {e}")
        finally:
            # Clean up connection
            with self.lock:
                if client_ip in self.connections:
                    del self.connections[client_ip]
            
            connection.close()
            logger.info(f"Client {client_ip} disconnected")
    
    def get_connection(self, ip: str) -> Optional[SnitchConnection]:
        """Get connection by IP address."""
        with self.lock:
            return self.connections.get(ip)
    
    def get_active_connections(self) -> list[dict[str, Any]]:
        """Get list of active connections."""
        with self.lock:
            connections = []
            for ip, conn in self.connections.items():
                if conn.connected:
                    connections.append({
                        "ip": ip,
                        "port": conn.address[1],
                        "connected_time": time.time() - conn.last_seen,
                        "last_seen": conn.last_seen
                    })
            return connections
    
    def send_command(self, ip: str, command: str, args: Optional[dict] = None) -> Optional[dict]:
        """Send command to specific client."""
        connection = self.get_connection(ip)
        if not connection:
            return None
        
        command_data = {
            "type": "command",
            "command": command,
            "args": args or {},
            "timestamp": time.time()
        }
        
        if not connection.send_encrypted(command_data):
            return None
        
        # Wait for response
        response = connection.receive_encrypted(timeout=30.0)
        if response:
            try:
                return json.loads(response.decode('utf-8'))
            except Exception as e:
                logger.error(f"Invalid response from {ip}: {e}")
        
        return None
    
    def stop_server(self) -> None:
        """Stop the server and close all connections."""
        self.running = False
        
        # Close all client connections
        with self.lock:
            for connection in self.connections.values():
                connection.close()
            self.connections.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        
        logger.info("Server stopped")


class SnitchClient:
    """Client for connecting to remote Snitch servers."""
    
    def __init__(self):
        self.connection: Optional[SnitchConnection] = None
    
    def connect(self, host: str, port: int) -> bool:
        """Connect to remote server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((host, port))
            
            self.connection = SnitchConnection(sock, (host, port))
            
            # Receive handshake
            handshake = self.connection.receive_encrypted(timeout=10.0)
            if handshake:
                try:
                    server_info = json.loads(handshake.decode('utf-8'))
                    logger.info(f"Connected to server: {server_info}")
                    
                    # Send client info
                    import platform
                    client_info = {
                        "type": "client_info",
                        "platform": platform.system(),
                        "hostname": platform.node(),
                        "user": os.getenv('USERNAME', 'unknown'),
                        "timestamp": time.time()
                    }
                    
                    self.connection.send_encrypted(client_info)
                    return True
                    
                except Exception as e:
                    logger.error(f"Handshake failed: {e}")
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            return False
    
    def send_command(self, command: str, args: Optional[dict] = None) -> Optional[dict]:
        """Send command to server."""
        if not self.connection or not self.connection.connected:
            return None
        
        command_data = {
            "type": "command",
            "command": command,
            "args": args or {},
            "timestamp": time.time()
        }
        
        if not self.connection.send_encrypted(command_data):
            return None
        
        # Wait for response
        response = self.connection.receive_encrypted(timeout=30.0)
        if response:
            try:
                return json.loads(response.decode('utf-8'))
            except Exception as e:
                logger.error(f"Invalid response: {e}")
        
        return None
    
    def disconnect(self) -> None:
        """Disconnect from server."""
        if self.connection:
            self.connection.close()
            self.connection = None


# Global server instance
server = SnitchServer()
"""
Windows shell interface for Snitch application.
"""
from __future__ import annotations

import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class WindowsShell:
    """Windows-specific shell operations."""
    
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
        self.current_directory = Path.cwd()
    
    def execute_command(self, command: str, timeout: int = 30) -> dict[str, Any]:
        """Execute a command and return result."""
        try:
            # Handle built-in commands
            if command.lower().startswith('cd '):
                return self._handle_cd(command[3:].strip())
            elif command.lower() in ['pwd', 'cd']:
                return {"success": True, "output": str(self.current_directory)}
            elif command.lower() in ['dir', 'ls']:
                return self._handle_dir()
            
            # Execute external command
            if self.is_windows:
                # Use cmd.exe for Windows commands
                full_command = ['cmd', '/c', command]
            else:
                # Use shell for Unix-like systems
                full_command = ['/bin/sh', '-c', command]
            
            result = subprocess.run(
                full_command,
                cwd=self.current_directory,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
            
            return {
                "success": result.returncode == 0,
                "output": output.strip(),
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds"
            }
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _handle_cd(self, path: str) -> dict[str, Any]:
        """Handle directory change command."""
        try:
            if not path:
                # No path provided, return current directory
                return {"success": True, "output": str(self.current_directory)}
            
            # Resolve path
            if Path(path).is_absolute():
                new_path = Path(path)
            else:
                new_path = self.current_directory / path
            
            # Resolve and normalize path
            new_path = new_path.resolve()
            
            if not new_path.exists():
                return {
                    "success": False,
                    "error": f"Directory not found: {path}"
                }
            
            if not new_path.is_dir():
                return {
                    "success": False,
                    "error": f"Not a directory: {path}"
                }
            
            self.current_directory = new_path
            return {
                "success": True,
                "output": str(self.current_directory),
                "path": str(self.current_directory)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to change directory: {e}"
            }
    
    def _handle_dir(self) -> dict[str, Any]:
        """Handle directory listing command."""
        try:
            files = []
            
            for item in self.current_directory.iterdir():
                try:
                    stat = item.stat()
                    files.append({
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": stat.st_mtime
                    })
                except (OSError, PermissionError):
                    # Skip files we can't access
                    continue
            
            # Sort: directories first, then files
            files.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
            
            # Format output
            output_lines = [f"Directory of {self.current_directory}\n"]
            
            for file_info in files:
                file_type = "<DIR>" if file_info["is_dir"] else ""
                size = "" if file_info["is_dir"] else f"{file_info['size']:>10,}"
                name = file_info["name"]
                
                output_lines.append(f"{file_type:5s} {size:>12s} {name}")
            
            return {
                "success": True,
                "output": "\n".join(output_lines),
                "files": files
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to list directory: {e}"
            }
    
    def get_system_info(self) -> dict[str, Any]:
        """Get comprehensive system information."""
        try:
            info = {
                "os": platform.system(),
                "platform": platform.platform(),
                "hostname": platform.node(),
                "user": os.getenv('USERNAME') or os.getenv('USER', 'unknown'),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "python_version": sys.version,
                "current_directory": str(self.current_directory)
            }
            
            # Windows-specific information
            if self.is_windows:
                try:
                    import winreg
                    
                    # Get Windows version
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                      r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                        info["windows_version"] = winreg.QueryValueEx(key, "ProductName")[0]
                        info["windows_build"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                except Exception:
                    pass
                
                # Get drive information
                try:
                    drives = []
                    for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        drive_path = f"{drive}:\\"
                        if os.path.exists(drive_path):
                            try:
                                stat = os.statvfs(drive_path) if hasattr(os, 'statvfs') else None
                                drives.append({
                                    "drive": drive,
                                    "path": drive_path,
                                    "exists": True
                                })
                            except Exception:
                                drives.append({
                                    "drive": drive,
                                    "path": drive_path,
                                    "exists": True
                                })
                    
                    info["drives"] = drives
                except Exception:
                    pass
            
            return {
                "success": True,
                "data": info
            }
            
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def take_screenshot(self) -> dict[str, Any]:
        """Take a screenshot of the desktop."""
        try:
            from PIL import ImageGrab
            import base64
            import io
            
            # Take screenshot
            screenshot = ImageGrab.grab()
            
            # Convert to bytes
            img_buffer = io.BytesIO()
            screenshot.save(img_buffer, format='PNG')
            img_data = img_buffer.getvalue()
            
            # Encode as base64
            img_b64 = base64.b64encode(img_data).decode('ascii')
            
            return {
                "success": True,
                "data": img_b64,
                "size": len(img_data),
                "format": "PNG"
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "PIL (Pillow) not available for screenshots"
            }
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_processes(self) -> dict[str, Any]:
        """Get list of running processes."""
        try:
            processes = []
            
            if self.is_windows:
                # Use tasklist on Windows
                result = subprocess.run(
                    ['tasklist', '/fo', 'csv'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        try:
                            parts = [p.strip('"') for p in line.split('","')]
                            if len(parts) >= 5:
                                processes.append({
                                    "name": parts[0],
                                    "pid": int(parts[1]),
                                    "session": parts[2],
                                    "session_num": parts[3],
                                    "memory": parts[4]
                                })
                        except (ValueError, IndexError):
                            continue
            else:
                # Use ps on Unix-like systems
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        try:
                            parts = line.split(None, 10)
                            if len(parts) >= 11:
                                processes.append({
                                    "user": parts[0],
                                    "pid": int(parts[1]),
                                    "cpu": float(parts[2]),
                                    "memory": float(parts[3]),
                                    "name": parts[10]
                                })
                        except (ValueError, IndexError):
                            continue
            
            return {
                "success": True,
                "processes": processes[:50]  # Limit to first 50
            }
            
        except Exception as e:
            logger.error(f"Failed to get processes: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def kill_process(self, pid: int) -> dict[str, Any]:
        """Kill a process by PID."""
        try:
            if self.is_windows:
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
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout + result.stderr
            }
            
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def lock_screen(self) -> dict[str, Any]:
        """Lock the screen."""
        try:
            if self.is_windows:
                # Use rundll32 to lock Windows screen
                result = subprocess.run(
                    ['rundll32.exe', 'user32.dll,LockWorkStation'],
                    capture_output=True
                )
                
                return {
                    "success": True,
                    "message": "Screen locked"
                }
            else:
                # Try common screen lockers on Unix-like systems
                lockers = ['gnome-screensaver-command -l', 'xscreensaver-command -lock']
                
                for locker in lockers:
                    try:
                        result = subprocess.run(
                            locker.split(),
                            capture_output=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            return {
                                "success": True,
                                "message": "Screen locked"
                            }
                    except Exception:
                        continue
                
                return {
                    "success": False,
                    "error": "No screen locker available"
                }
                
        except Exception as e:
            logger.error(f"Failed to lock screen: {e}")
            return {
                "success": False,
                "error": str(e)
            }


# Global shell instance
shell = WindowsShell()
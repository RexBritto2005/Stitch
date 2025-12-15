"""
Help and command documentation for Snitch application.
"""
from __future__ import annotations

from colorama import Fore, Style, init

# Initialize colorama for Windows
init(autoreset=True)


def print_banner() -> None:
    """Print application banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    {Fore.WHITE}Snitch Python 3.13{Fore.CYAN}                        ║
║                 {Fore.YELLOW}Remote Administration Tool{Fore.CYAN}                   ║
║                                                              ║
║  {Fore.GREEN}Secure • Modern • Cross-Platform • Unique Encryption{Fore.CYAN}     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_help() -> None:
    """Print comprehensive help information."""
    help_text = f"""
{Fore.YELLOW}═══════════════════════════════════════════════════════════════
                        SNITCH COMMANDS
═══════════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.GREEN}SERVER MANAGEMENT:{Style.RESET_ALL}
  {Fore.CYAN}listen <port>{Style.RESET_ALL}          Start server on specified port (default: 4040)
  {Fore.CYAN}stop{Style.RESET_ALL}                   Stop the server
  {Fore.CYAN}status{Style.RESET_ALL}                 Show server status

{Fore.GREEN}CONNECTION MANAGEMENT:{Style.RESET_ALL}
  {Fore.CYAN}connect <ip> <port>{Style.RESET_ALL}    Connect to remote payload
  {Fore.CYAN}sessions{Style.RESET_ALL}               Show active client connections
  {Fore.CYAN}disconnect <ip>{Style.RESET_ALL}        Disconnect specific client
  {Fore.CYAN}history{Style.RESET_ALL}                Show connection history

{Fore.GREEN}REMOTE SHELL:{Style.RESET_ALL}
  {Fore.CYAN}shell <ip>{Style.RESET_ALL}             Interactive shell with specific client
  {Fore.CYAN}cmd <ip> <command>{Style.RESET_ALL}     Execute single command on client
  {Fore.CYAN}sysinfo <ip>{Style.RESET_ALL}           Get system information from client

{Fore.GREEN}FILE OPERATIONS:{Style.RESET_ALL}
  {Fore.CYAN}upload <ip> <local> <remote>{Style.RESET_ALL}   Upload file to client
  {Fore.CYAN}download <ip> <remote> <local>{Style.RESET_ALL} Download file from client
  {Fore.CYAN}ls <ip> [path]{Style.RESET_ALL}         List directory contents on client
  {Fore.CYAN}pwd <ip>{Style.RESET_ALL}               Show current directory on client
  {Fore.CYAN}cd <ip> <path>{Style.RESET_ALL}         Change directory on client

{Fore.GREEN}SYSTEM CONTROL:{Style.RESET_ALL}
  {Fore.CYAN}screenshot <ip>{Style.RESET_ALL}        Take screenshot from client
  {Fore.CYAN}processes <ip>{Style.RESET_ALL}         List running processes on client
  {Fore.CYAN}kill <ip> <pid>{Style.RESET_ALL}        Kill process on client
  {Fore.CYAN}lock <ip>{Style.RESET_ALL}              Lock client screen

{Fore.GREEN}ENCRYPTION MANAGEMENT:{Style.RESET_ALL}
  {Fore.CYAN}showkey{Style.RESET_ALL}                Display current AES encryption key
  {Fore.CYAN}addkey <base64_key>{Style.RESET_ALL}    Add AES key to library
  {Fore.CYAN}listkeys{Style.RESET_ALL}               Show all keys in library
  {Fore.CYAN}genkey{Style.RESET_ALL}                 Generate new random AES key

{Fore.GREEN}PAYLOAD GENERATION:{Style.RESET_ALL}
  {Fore.CYAN}generate <type> <ip> <port>{Style.RESET_ALL}    Generate payload
  {Fore.CYAN}payloads{Style.RESET_ALL}               List available payload types

{Fore.GREEN}GENERAL:{Style.RESET_ALL}
  {Fore.CYAN}help{Style.RESET_ALL}                   Show this help message
  {Fore.CYAN}clear{Style.RESET_ALL}                  Clear screen
  {Fore.CYAN}exit{Style.RESET_ALL}                   Exit Snitch application

{Fore.YELLOW}═══════════════════════════════════════════════════════════════
                         EXAMPLES
═══════════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.GREEN}Start server:{Style.RESET_ALL}
  {Fore.WHITE}listen 4040{Style.RESET_ALL}

{Fore.GREEN}Connect to remote payload:{Style.RESET_ALL}
  {Fore.WHITE}connect 192.168.1.100 4040{Style.RESET_ALL}

{Fore.GREEN}Interactive shell:{Style.RESET_ALL}
  {Fore.WHITE}shell 192.168.1.100{Style.RESET_ALL}

{Fore.GREEN}Upload file:{Style.RESET_ALL}
  {Fore.WHITE}upload 192.168.1.100 C:\\local\\file.txt /tmp/remote_file.txt{Style.RESET_ALL}

{Fore.GREEN}Add custom AES key:{Style.RESET_ALL}
  {Fore.WHITE}addkey dGhpcyBpcyBhIDMyIGJ5dGUgQUVTIGtleSBmb3IgdGVzdGluZw=={Style.RESET_ALL}

{Fore.YELLOW}═══════════════════════════════════════════════════════════════
                      SECURITY NOTES
═══════════════════════════════════════════════════════════════{Style.RESET_ALL}

• Each installation generates a unique 32-byte AES key
• All communications are encrypted using AES CFB mode
• Keys are never hardcoded - generated using cryptographically secure methods
• Use environment variable {Fore.CYAN}Snitch_AES_KEY{Style.RESET_ALL} for custom keys
• Key files are automatically excluded from version control

{Fore.RED}WARNING: This tool is for educational and authorized testing only!{Style.RESET_ALL}
"""
    print(help_text)


def print_key_help() -> None:
    """Print AES key management help."""
    key_help = f"""
{Fore.YELLOW}═══════════════════════════════════════════════════════════════
                    AES KEY MANAGEMENT
═══════════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.GREEN}KEY GENERATION:{Style.RESET_ALL}
• Each Snitch installation automatically generates a unique 32-byte AES key
• Keys are generated using Python's {Fore.CYAN}secrets{Style.RESET_ALL} module for cryptographic security
• Keys are Base64 encoded (44 characters) for storage and transmission

{Fore.GREEN}KEY STORAGE:{Style.RESET_ALL}
• Primary key: {Fore.CYAN}Application/Snitch_Vars/st_aes.py{Style.RESET_ALL}
• Key library: {Fore.CYAN}Application/Snitch_Vars/st_aes_lib.ini{Style.RESET_ALL}
• Both files are automatically excluded from version control

{Fore.GREEN}CUSTOM KEYS:{Style.RESET_ALL}
• Set environment variable: {Fore.CYAN}Snitch_AES_KEY=<base64_key>{Style.RESET_ALL}
• Key must be exactly 32 bytes when Base64 decoded
• Use {Fore.CYAN}addkey{Style.RESET_ALL} command to add keys to library

{Fore.GREEN}KEY ABBREVIATIONS:{Style.RESET_ALL}
• Keys are abbreviated using MD5 hash (first 13 characters)
• Abbreviations are alphanumeric only (safe for config files)
• Used for organizing multiple keys in the library

{Fore.GREEN}EXAMPLES:{Style.RESET_ALL}
  {Fore.WHITE}# Show current key information
  showkey

  # Add a new key to library
  addkey dGhpcyBpcyBhIDMyIGJ5dGUgQUVTIGtleSBmb3IgdGVzdGluZw==

  # Generate new random key
  genkey

  # List all keys in library
  listkeys{Style.RESET_ALL}

{Fore.RED}SECURITY REMINDER:{Style.RESET_ALL}
• Never share or commit AES keys to version control
• Use unique keys for each deployment
• Rotate keys regularly for enhanced security
"""
    print(key_help)


def print_payload_help() -> None:
    """Print payload generation help."""
    payload_help = f"""
{Fore.YELLOW}═══════════════════════════════════════════════════════════════
                   PAYLOAD GENERATION
═══════════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.GREEN}AVAILABLE PAYLOAD TYPES:{Style.RESET_ALL}
  {Fore.CYAN}python{Style.RESET_ALL}     - Python script payload (.py)
  {Fore.CYAN}exe{Style.RESET_ALL}        - Windows executable (.exe)
  {Fore.CYAN}powershell{Style.RESET_ALL} - PowerShell script (.ps1)
  {Fore.CYAN}batch{Style.RESET_ALL}      - Batch file (.bat)

{Fore.GREEN}GENERATION COMMAND:{Style.RESET_ALL}
  {Fore.WHITE}generate <type> <server_ip> <server_port>{Style.RESET_ALL}

{Fore.GREEN}EXAMPLES:{Style.RESET_ALL}
  {Fore.WHITE}# Generate Python payload
  generate python 192.168.1.50 4040

  # Generate Windows executable
  generate exe 10.0.0.100 8080

  # Generate PowerShell script
  generate powershell 172.16.1.10 4040{Style.RESET_ALL}

{Fore.GREEN}PAYLOAD FEATURES:{Style.RESET_ALL}
• Automatic AES encryption using current key
• Cross-platform compatibility (where applicable)
• Persistent connection with auto-reconnect
• Comprehensive system information gathering
• File upload/download capabilities
• Remote shell execution

{Fore.GREEN}OUTPUT LOCATION:{Style.RESET_ALL}
Generated payloads are saved to: {Fore.CYAN}Payloads/{Style.RESET_ALL} directory

{Fore.RED}LEGAL NOTICE:{Style.RESET_ALL}
Only use generated payloads on systems you own or have explicit permission to test.
"""
    print(payload_help)


def print_error(message: str) -> None:
    """Print error message in red."""
    print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")


def print_success(message: str) -> None:
    """Print success message in green."""
    print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")


def print_warning(message: str) -> None:
    """Print warning message in yellow."""
    print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")


def print_info(message: str) -> None:
    """Print info message in cyan."""
    print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}")
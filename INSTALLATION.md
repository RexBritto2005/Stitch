# Snitch Python 3.13 - Installation Guide

## 📋 System Requirements

- **Python 3.13+** (Required)
- **Windows 10/11** (Optimized), macOS 10.15+, or Linux
- **4GB RAM** minimum (8GB recommended)
- **100MB** free disk space
- **Administrator privileges** (for some payload operations)

## 🚀 Quick Installation

### 1. Download and Extract
```bash
# Download the Snitch Python 3.13 package
# Extract to your desired directory
cd Snitch_Python313
```

### 2. Install Dependencies
```bash
# Install required Python packages
pip install -r win_requirements.txt
```

### 3. Verify Installation
```bash
# Run the verification script
python verify_installation.py
```

### 4. Start Snitch
```bash
# Launch the application
python main.py
```

## 📦 Dependencies Explained

| Package | Purpose | Version |
|---------|---------|---------|
| `pycryptodome` | AES encryption/decryption | 3.19.0+ |
| `Pillow` | Screenshot functionality | 10.0.0+ |
| `pyreadline3` | Windows readline support | 3.4.1+ |
| `pywin32` | Windows API access | 306+ |
| `requests` | HTTP communications | 2.31.0+ |
| `colorama` | Cross-platform colored output | 0.4.6+ |
| `python-dateutil` | Date/time utilities | 2.8.2+ |

## 🔧 Manual Installation Steps

### Step 1: Python 3.13 Installation

**Windows:**
1. Download Python 3.13 from [python.org](https://python.org)
2. Run installer with "Add to PATH" checked
3. Verify: `python --version`

**macOS:**
```bash
# Using Homebrew
brew install python@3.13

# Or download from python.org
```

**Linux (Ubuntu/Debian):**
```bash
# Add deadsnakes PPA for Python 3.13
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.13 python3.13-pip
```

### Step 2: Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv snitch_env

# Activate (Windows)
snitch_env\Scripts\activate

# Activate (macOS/Linux)
source snitch_env/bin/activate

# Install dependencies
pip install -r win_requirements.txt
```

### Step 3: Verify Components

```bash
# Check Python version
python --version

# Check pip
pip --version

# Test imports
python -c "import Crypto, PIL, requests, colorama; print('All dependencies OK')"
```

## 🛠️ Troubleshooting

### Common Issues

**"Python 3.13 not found"**
- Ensure Python 3.13 is installed and in PATH
- Try `python3.13` instead of `python`
- Restart terminal after installation

**"pip install fails"**
```bash
# Update pip first
python -m pip install --upgrade pip

# Install with verbose output
pip install -v -r win_requirements.txt

# Use alternative index if needed
pip install -i https://pypi.org/simple/ -r win_requirements.txt
```

**"Permission denied" errors**
```bash
# Install for user only
pip install --user -r win_requirements.txt

# Or run as administrator (Windows)
# Or use sudo (macOS/Linux)
```

**"pycryptodome installation fails"**
```bash
# Windows: Install Visual Studio Build Tools
# Or use pre-compiled wheel
pip install --only-binary=all pycryptodome

# macOS: Install Xcode command line tools
xcode-select --install

# Linux: Install build essentials
sudo apt install build-essential python3.13-dev
```

**"pywin32 not available" (Non-Windows)**
- This is normal on macOS/Linux
- Windows-specific features will be disabled
- Core functionality remains available

### Platform-Specific Notes

**Windows:**
- Run as Administrator for full functionality
- Windows Defender may flag payloads (add exclusion)
- PowerShell execution policy may need adjustment

**macOS:**
- May need to allow app in Security & Privacy
- Some system operations require admin privileges
- Screenshot functionality requires screen recording permission

**Linux:**
- Install X11 development libraries for screenshots
- Some operations may require sudo privileges
- Firewall configuration may be needed

## 🔐 Security Configuration

### Firewall Settings

**Windows Firewall:**
```powershell
# Allow Snitch through firewall (run as admin)
netsh advfirewall firewall add rule name="Snitch Server" dir=in action=allow protocol=TCP localport=4040
```

**Linux iptables:**
```bash
# Allow incoming connections on port 4040
sudo iptables -A INPUT -p tcp --dport 4040 -j ACCEPT
```

**macOS:**
- System Preferences → Security & Privacy → Firewall
- Add Python to allowed applications

### Antivirus Exclusions

Add these directories to antivirus exclusions:
- `Snitch_Python313/` (entire directory)
- `Payloads/` (generated payloads)
- `Downloads/` (downloaded files)

## 📁 Directory Structure After Installation

```
Snitch_Python313/
├── main.py                          # ✅ Main entry point
├── README.md                        # ✅ Documentation
├── INSTALLATION.md                  # ✅ This file
├── verify_installation.py           # ✅ Verification script
├── win_requirements.txt             # ✅ Dependencies
├── .gitignore                       # ✅ Git exclusions
├── Application/                     # ✅ Core modules
│   ├── Snitch_cmd.py               # ✅ Command handling
│   ├── Snitch_lib.py               # ✅ Communication
│   ├── Snitch_utils.py             # ✅ Utilities
│   ├── Snitch_help.py              # ✅ Help system
│   ├── Snitch_gen.py               # ✅ Payload generation
│   ├── Snitch_winshell.py          # ✅ Shell interface
│   ├── Snitch_pyld_config.py       # ✅ Configuration
│   └── Snitch_Vars/
│       ├── globals.py              # ✅ Constants
│       ├── st_aes.py               # 🔐 Generated AES key
│       └── st_aes_lib.ini          # 🔐 Key library
├── Logs/                           # 📝 Application logs
├── Downloads/                      # 📥 Downloaded files
├── Uploads/                        # 📤 Files to upload
├── Payloads/                       # 🎯 Generated payloads
├── Temp/                           # 🗂️ Temporary files
├── Configuration/                  # ⚙️ Config files
├── Tools/                          # 🔧 Additional tools
└── PyLib/                          # 📚 Python libraries
```

## ✅ Installation Verification Checklist

Run `python verify_installation.py` and ensure all checks pass:

- [ ] Python 3.13+ detected
- [ ] All dependencies installed
- [ ] File structure complete
- [ ] AES key generation working
- [ ] Encryption functionality working
- [ ] Payload generation working
- [ ] Git configuration correct

## 🚀 First Run

After successful installation:

1. **Start Snitch:**
   ```bash
   python main.py
   ```

2. **Basic commands:**
   ```
   snitch> help              # Show all commands
   snitch> showkey           # Display AES key
   snitch> listen 4040       # Start server
   snitch> generate python 192.168.1.100 4040  # Generate payload
   ```

3. **Test connection:**
   - Generate a payload
   - Run payload on target system
   - Use `sessions` to see connections
   - Use `shell <ip>` for interactive access

## 📞 Support

If you encounter issues:

1. **Check logs:** `Logs/snitch.log`
2. **Run verification:** `python verify_installation.py`
3. **Check permissions:** Ensure write access to directories
4. **Review firewall:** Allow Python through firewall
5. **Update dependencies:** `pip install --upgrade -r win_requirements.txt`

## 🔄 Updating

To update Snitch:

1. **Backup configuration:**
   ```bash
   cp -r Configuration/ Configuration_backup/
   cp Application/Snitch_Vars/st_aes.py st_aes_backup.py
   ```

2. **Download new version**

3. **Restore configuration:**
   ```bash
   cp Configuration_backup/* Configuration/
   cp st_aes_backup.py Application/Snitch_Vars/st_aes.py
   ```

4. **Update dependencies:**
   ```bash
   pip install --upgrade -r win_requirements.txt
   ```

---

**Ready to use Snitch? Run `python main.py` to get started!** 🎉
#!/usr/bin/env python3
"""
Snitch Python 3.13 - Installation Verification Script

This script verifies that Snitch is properly installed and configured.
"""
import sys
from pathlib import Path

def check_python_version():
    """Verify Python version is 3.13+."""
    print("🔍 Checking Python version...")
    
    if sys.version_info >= (3, 13):
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} - OK")
        return True
    else:
        print(f"❌ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} - Requires 3.13+")
        return False

def check_dependencies():
    """Check if all required dependencies are available."""
    print("\n🔍 Checking dependencies...")
    
    required_modules = {
        'Crypto': 'pycryptodome',
        'PIL': 'Pillow',
        'requests': 'requests',
        'colorama': 'colorama',
        'dateutil': 'python-dateutil'
    }
    
    missing = []
    
    for module, package in required_modules.items():
        try:
            __import__(module)
            print(f"✅ {package} - OK")
        except ImportError:
            print(f"❌ {package} - MISSING")
            missing.append(package)
    
    if missing:
        print(f"\n📦 Install missing packages:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    return True

def check_file_structure():
    """Verify file structure is correct."""
    print("\n🔍 Checking file structure...")
    
    required_files = [
        "main.py",
        "README.md",
        "win_requirements.txt",
        ".gitignore",
        "Application/Snitch_cmd.py",
        "Application/Snitch_lib.py",
        "Application/Snitch_utils.py",
        "Application/Snitch_help.py",
        "Application/Snitch_gen.py",
        "Application/Snitch_Vars/globals.py"
    ]
    
    required_dirs = [
        "Application",
        "Application/Snitch_Vars",
        "Logs",
        "Downloads", 
        "Uploads",
        "Payloads",
        "Temp",
        "Configuration"
    ]
    
    missing_files = []
    missing_dirs = []
    
    # Check files
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            missing_files.append(file_path)
    
    # Check directories
    for dir_path in required_dirs:
        if Path(dir_path).is_dir():
            print(f"✅ {dir_path}/")
        else:
            print(f"❌ {dir_path}/ - MISSING")
            missing_dirs.append(dir_path)
    
    return len(missing_files) == 0 and len(missing_dirs) == 0

def check_aes_key_generation():
    """Test AES key generation."""
    print("\n🔍 Checking AES key generation...")
    
    try:
        # Add Application to path
        APP_DIR = Path(__file__).parent / "Application"
        sys.path.insert(0, str(APP_DIR))
        
        from Application.Snitch_utils import crypto
        
        key_info = crypto.get_current_key_info()
        
        if "error" in key_info:
            print(f"❌ Key generation failed: {key_info['error']}")
            return False
        
        # Verify key properties
        if key_info['key_length'] != 32:
            print(f"❌ Invalid key length: {key_info['key_length']} (expected 32)")
            return False
        
        if len(key_info['key_encoded']) != 44:  # Base64 encoded 32 bytes = 44 chars
            print(f"❌ Invalid encoded key length: {len(key_info['key_encoded'])} (expected 44)")
            return False
        
        print(f"✅ AES key generated successfully")
        print(f"   Key abbreviation: {key_info['key_abbrev']}")
        print(f"   Key length: {key_info['key_length']} bytes")
        
        return True
        
    except Exception as e:
        print(f"❌ AES key check failed: {e}")
        return False

def check_encryption():
    """Test encryption/decryption."""
    print("\n🔍 Checking encryption functionality...")
    
    try:
        from Application.Snitch_utils import crypto
        
        test_data = "Snitch verification test message"
        
        # Encrypt
        encrypted = crypto.encrypt_data(test_data)
        
        # Decrypt
        decrypted = crypto.decrypt_data(encrypted)
        decrypted_str = decrypted.decode('utf-8')
        
        if decrypted_str == test_data:
            print("✅ Encryption/decryption working correctly")
            return True
        else:
            print("❌ Encryption/decryption failed - data mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Encryption check failed: {e}")
        return False

def check_payload_generation():
    """Test payload generation."""
    print("\n🔍 Checking payload generation...")
    
    try:
        from Application.Snitch_gen import payload_generator
        
        # Test Python payload generation
        payload_path = payload_generator.generate_python_payload("127.0.0.1", 4040)
        
        if payload_path and payload_path.exists():
            size = payload_path.stat().st_size
            print(f"✅ Payload generation working (test file: {size:,} bytes)")
            
            # Clean up test file
            payload_path.unlink()
            
            return True
        else:
            print("❌ Payload generation failed")
            return False
            
    except Exception as e:
        print(f"❌ Payload generation check failed: {e}")
        return False

def check_gitignore():
    """Verify .gitignore is properly configured."""
    print("\n🔍 Checking .gitignore configuration...")
    
    gitignore_path = Path(".gitignore")
    
    if not gitignore_path.exists():
        print("❌ .gitignore file missing")
        return False
    
    try:
        with open(gitignore_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        required_patterns = [
            "Application/Snitch_Vars/st_aes.py",
            "Application/Snitch_Vars/st_aes_lib.ini",
            "Downloads/",
            "Uploads/",
            "Logs/",
            "Payloads/"
        ]
        
        missing_patterns = []
        
        for pattern in required_patterns:
            if pattern in content:
                print(f"✅ {pattern}")
            else:
                print(f"❌ {pattern} - MISSING")
                missing_patterns.append(pattern)
        
        return len(missing_patterns) == 0
        
    except Exception as e:
        print(f"❌ .gitignore check failed: {e}")
        return False

def main():
    """Run all verification checks."""
    print("Snitch Python 3.13 - Installation Verification")
    print("=" * 60)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("File Structure", check_file_structure),
        ("AES Key Generation", check_aes_key_generation),
        ("Encryption", check_encryption),
        ("Payload Generation", check_payload_generation),
        ("Git Configuration", check_gitignore)
    ]
    
    passed = 0
    total = len(checks)
    
    for name, check_func in checks:
        print(f"\n{'='*20} {name} {'='*20}")
        
        if check_func():
            passed += 1
        else:
            print(f"\n⚠️  {name} check failed!")
    
    print("\n" + "=" * 60)
    print(f"Verification Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 Snitch is properly installed and ready to use!")
        print("\nNext steps:")
        print("1. Run: python main.py")
        print("2. Type 'help' for available commands")
        print("3. Start with: listen 4040")
        return 0
    else:
        print(f"\n❌ {total - passed} checks failed. Please fix the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
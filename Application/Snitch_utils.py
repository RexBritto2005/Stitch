"""
Utility functions and encryption for Snitch application.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from pathlib import Path
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .Snitch_Vars.globals import AES_KEY_FILE, AES_LIB_FILE

logger = logging.getLogger(__name__)


class SnitchCrypto:
    """Handles AES encryption/decryption for Snitch communications."""
    
    def __init__(self):
        self.current_key: Optional[bytes] = None
        self.key_library: dict[str, str] = {}
        self._load_or_generate_key()
        self._load_key_library()
    
    def _generate_unique_key(self) -> tuple[bytes, str]:
        """Generate a cryptographically unique AES key."""
        key_bytes = secrets.token_bytes(32)
        key_encoded = base64.b64encode(key_bytes).decode('ascii')
        
        # Create safe abbreviation using MD5 hash
        key_hash = hashlib.md5(key_encoded.encode()).hexdigest()
        key_abbrev = key_hash[:13]  # Alphanumeric only
        
        logger.info(f"Generated new unique AES key with abbreviation: {key_abbrev}")
        return key_bytes, key_encoded, key_abbrev
    
    def _load_or_generate_key(self) -> None:
        """Load existing key or generate new one."""
        # Check for custom key in environment
        env_key = os.getenv('Snitch_AES_KEY')
        if env_key:
            try:
                key_bytes = base64.b64decode(env_key)
                if len(key_bytes) == 32:
                    self.current_key = key_bytes
                    logger.info("Using AES key from environment variable")
                    return
                else:
                    logger.warning("Environment AES key invalid length, generating new key")
            except Exception as e:
                logger.warning(f"Invalid environment AES key: {e}, generating new key")
        
        # Try to load existing key file
        if AES_KEY_FILE.exists():
            try:
                with open(AES_KEY_FILE, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Extract key from Python file format
                    for line in content.split('\n'):
                        if line.startswith('aes_encoded = '):
                            key_str = line.split('"')[1]
                            self.current_key = base64.b64decode(key_str)
                            logger.info("Loaded existing AES key")
                            return
            except Exception as e:
                logger.warning(f"Failed to load existing key: {e}")
        
        # Generate new key
        key_bytes, key_encoded, key_abbrev = self._generate_unique_key()
        self.current_key = key_bytes
        
        # Save key to file
        self._save_key_file(key_encoded, key_abbrev)
    
    def _save_key_file(self, key_encoded: str, key_abbrev: str) -> None:
        """Save AES key to Python file."""
        key_content = f'''"""
Auto-generated AES key for Snitch application.
DO NOT COMMIT THIS FILE TO VERSION CONTROL.
"""
from __future__ import annotations

# Unique AES key for this installation
aes_encoded = "{key_encoded}"
aes_abbrev = "{key_abbrev}"

# Key bytes (32 bytes)
import base64
aes_key = base64.b64decode(aes_encoded)
'''
        
        try:
            with open(AES_KEY_FILE, 'w', encoding='utf-8') as f:
                f.write(key_content)
            logger.info(f"Saved AES key to {AES_KEY_FILE}")
        except Exception as e:
            logger.error(f"Failed to save AES key: {e}")
    
    def _load_key_library(self) -> None:
        """Load AES key library from INI file."""
        if not AES_LIB_FILE.exists():
            return
        
        try:
            with open(AES_LIB_FILE, 'r', encoding='utf-8') as f:
                current_section = None
                for line in f:
                    line = line.strip()
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1]
                    elif '=' in line and current_section:
                        key, value = line.split('=', 1)
                        if key.strip() == 'aes_encoded':
                            self.key_library[current_section] = value.strip()
            
            logger.info(f"Loaded {len(self.key_library)} keys from library")
        except Exception as e:
            logger.warning(f"Failed to load key library: {e}")
    
    def add_key_to_library(self, key_encoded: str) -> bool:
        """Add a new key to the library."""
        try:
            # Validate key
            key_bytes = base64.b64decode(key_encoded)
            if len(key_bytes) != 32:
                logger.error("Key must be exactly 32 bytes when decoded")
                return False
            
            # Create abbreviation
            key_hash = hashlib.md5(key_encoded.encode()).hexdigest()
            key_abbrev = key_hash[:13]
            
            # Add to library
            self.key_library[key_abbrev] = key_encoded
            
            # Save to file
            self._save_key_library()
            
            logger.info(f"Added key to library with abbreviation: {key_abbrev}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add key to library: {e}")
            return False
    
    def _save_key_library(self) -> None:
        """Save key library to INI file."""
        try:
            with open(AES_LIB_FILE, 'w', encoding='utf-8') as f:
                for abbrev, key in self.key_library.items():
                    f.write(f"[{abbrev}]\n")
                    f.write(f"aes_encoded = {key}\n\n")
            
            logger.info(f"Saved key library with {len(self.key_library)} keys")
        except Exception as e:
            logger.error(f"Failed to save key library: {e}")
    
    def encrypt_data(self, data: str | bytes, key: Optional[bytes] = None) -> bytes:
        """Encrypt data using AES CFB mode with random IV."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encryption_key = key or self.current_key
        if not encryption_key:
            raise ValueError("No encryption key available")
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Create cipher and encrypt
        cipher = AES.new(encryption_key, AES.MODE_CFB, iv)
        encrypted_data = cipher.encrypt(data)
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    def decrypt_data(self, encrypted_data: bytes, key: Optional[bytes] = None) -> bytes:
        """Decrypt data using AES CFB mode."""
        decryption_key = key or self.current_key
        if not decryption_key:
            raise ValueError("No decryption key available")
        
        if len(encrypted_data) < 16:
            raise ValueError("Encrypted data too short")
        
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher and decrypt
        cipher = AES.new(decryption_key, AES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        
        return decrypted_data
    
    def get_current_key_info(self) -> dict[str, str]:
        """Get information about the current key."""
        if not self.current_key:
            return {"error": "No key loaded"}
        
        key_encoded = base64.b64encode(self.current_key).decode('ascii')
        key_hash = hashlib.md5(key_encoded.encode()).hexdigest()
        key_abbrev = key_hash[:13]
        
        return {
            "key_encoded": key_encoded,
            "key_abbrev": key_abbrev,
            "key_length": len(self.current_key),
            "library_keys": len(self.key_library)
        }


# Global crypto instance
crypto = SnitchCrypto()


def setup_logging(log_level: str = "INFO") -> None:
    """Setup logging configuration."""
    from .Snitch_Vars.globals import LOGS_DIR
    
    log_file = LOGS_DIR / "snitch.log"
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )


def validate_ip(ip: str) -> bool:
    """Validate IP address format."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def validate_port(port: str | int) -> bool:
    """Validate port number."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False
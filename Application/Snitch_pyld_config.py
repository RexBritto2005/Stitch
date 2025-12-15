"""
Payload configuration for Snitch application.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from .Snitch_Vars.globals import CONFIG_DIR

logger = logging.getLogger(__name__)


class PayloadConfig:
    """Manages payload configuration and templates."""
    
    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "payload_config.json"
        self.templates_dir = self.config_dir / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        
        self.config = self._load_config()
    
    def _load_config(self) -> dict[str, Any]:
        """Load payload configuration from file."""
        default_config = {
            "default_settings": {
                "reconnect_delay": 5,
                "max_reconnect_attempts": 10,
                "connection_timeout": 10,
                "command_timeout": 30,
                "keepalive_interval": 60,
                "max_message_size": 10485760  # 10MB
            },
            "payload_types": {
                "python": {
                    "extension": ".py",
                    "template": "python_template.py",
                    "dependencies": ["pycryptodome", "pillow"],
                    "description": "Python script payload with full functionality"
                },
                "powershell": {
                    "extension": ".ps1",
                    "template": "powershell_template.ps1",
                    "dependencies": [],
                    "description": "PowerShell script for Windows systems"
                },
                "batch": {
                    "extension": ".bat",
                    "template": "batch_template.bat",
                    "dependencies": [],
                    "description": "Windows batch file for basic operations"
                },
                "exe": {
                    "extension": ".exe",
                    "template": "python_template.py",
                    "dependencies": ["pyinstaller"],
                    "description": "Windows executable (requires compilation)"
                }
            },
            "encoding_options": {
                "base64": True,
                "compression": False,
                "obfuscation": False
            },
            "security_settings": {
                "require_encryption": True,
                "validate_certificates": False,
                "use_random_delays": True,
                "anti_debug": False
            }
        }
        
        if not self.config_file.exists():
            self._save_config(default_config)
            return default_config
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Merge with defaults for any missing keys
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to load payload config: {e}")
            return default_config
    
    def _save_config(self, config: dict[str, Any]) -> None:
        """Save payload configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            logger.info("Payload configuration saved")
            
        except Exception as e:
            logger.error(f"Failed to save payload config: {e}")
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set_setting(self, key: str, value: Any) -> None:
        """Set a configuration setting."""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
        
        # Save configuration
        self._save_config(self.config)
    
    def get_payload_types(self) -> dict[str, dict[str, Any]]:
        """Get available payload types and their configurations."""
        return self.config.get("payload_types", {})
    
    def get_payload_config(self, payload_type: str) -> Optional[dict[str, Any]]:
        """Get configuration for a specific payload type."""
        payload_types = self.get_payload_types()
        return payload_types.get(payload_type.lower())
    
    def add_payload_type(self, name: str, config: dict[str, Any]) -> None:
        """Add a new payload type configuration."""
        if "payload_types" not in self.config:
            self.config["payload_types"] = {}
        
        self.config["payload_types"][name.lower()] = config
        self._save_config(self.config)
        
        logger.info(f"Added payload type: {name}")
    
    def remove_payload_type(self, name: str) -> bool:
        """Remove a payload type configuration."""
        if "payload_types" in self.config and name.lower() in self.config["payload_types"]:
            del self.config["payload_types"][name.lower()]
            self._save_config(self.config)
            logger.info(f"Removed payload type: {name}")
            return True
        
        return False
    
    def create_template(self, payload_type: str, template_content: str) -> bool:
        """Create a payload template file."""
        try:
            payload_config = self.get_payload_config(payload_type)
            if not payload_config:
                logger.error(f"Unknown payload type: {payload_type}")
                return False
            
            template_name = payload_config.get("template", f"{payload_type}_template")
            template_path = self.templates_dir / template_name
            
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            logger.info(f"Created template: {template_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create template: {e}")
            return False
    
    def load_template(self, payload_type: str) -> Optional[str]:
        """Load a payload template."""
        try:
            payload_config = self.get_payload_config(payload_type)
            if not payload_config:
                return None
            
            template_name = payload_config.get("template", f"{payload_type}_template")
            template_path = self.templates_dir / template_name
            
            if not template_path.exists():
                return None
            
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Failed to load template: {e}")
            return None
    
    def get_default_settings(self) -> dict[str, Any]:
        """Get default payload settings."""
        return self.config.get("default_settings", {})
    
    def get_security_settings(self) -> dict[str, Any]:
        """Get security settings."""
        return self.config.get("security_settings", {})
    
    def validate_payload_config(self, payload_type: str) -> tuple[bool, list[str]]:
        """Validate payload configuration."""
        errors = []
        
        payload_config = self.get_payload_config(payload_type)
        if not payload_config:
            errors.append(f"Unknown payload type: {payload_type}")
            return False, errors
        
        # Check required fields
        required_fields = ["extension", "template", "description"]
        for field in required_fields:
            if field not in payload_config:
                errors.append(f"Missing required field: {field}")
        
        # Check template exists
        template_name = payload_config.get("template")
        if template_name:
            template_path = self.templates_dir / template_name
            if not template_path.exists():
                errors.append(f"Template file not found: {template_name}")
        
        return len(errors) == 0, errors
    
    def export_config(self, export_path: Path) -> bool:
        """Export configuration to file."""
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            
            logger.info(f"Configuration exported to: {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return False
    
    def import_config(self, import_path: Path) -> bool:
        """Import configuration from file."""
        try:
            if not import_path.exists():
                logger.error(f"Import file not found: {import_path}")
                return False
            
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Validate imported config
            if not isinstance(imported_config, dict):
                logger.error("Invalid configuration format")
                return False
            
            # Merge with existing config
            self.config.update(imported_config)
            self._save_config(self.config)
            
            logger.info(f"Configuration imported from: {import_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        if self.config_file.exists():
            self.config_file.unlink()
        
        self.config = self._load_config()
        logger.info("Configuration reset to defaults")
    
    def get_config_summary(self) -> dict[str, Any]:
        """Get a summary of the current configuration."""
        return {
            "payload_types": len(self.get_payload_types()),
            "templates_available": len(list(self.templates_dir.glob("*"))),
            "config_file": str(self.config_file),
            "templates_dir": str(self.templates_dir),
            "security_enabled": self.get_setting("security_settings.require_encryption", True),
            "default_timeout": self.get_setting("default_settings.connection_timeout", 10)
        }


# Global payload config instance
payload_config = PayloadConfig()
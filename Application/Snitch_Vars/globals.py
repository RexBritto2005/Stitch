"""
Global constants and paths for Snitch application.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Final

# Application paths
APP_ROOT: Final[Path] = Path(__file__).parent.parent.parent
APP_DIR: Final[Path] = APP_ROOT / "Application"
VARS_DIR: Final[Path] = APP_DIR / "Snitch_Vars"
LOGS_DIR: Final[Path] = APP_ROOT / "Logs"
DOWNLOADS_DIR: Final[Path] = APP_ROOT / "Downloads"
UPLOADS_DIR: Final[Path] = APP_ROOT / "Uploads"
PAYLOADS_DIR: Final[Path] = APP_ROOT / "Payloads"
TEMP_DIR: Final[Path] = APP_ROOT / "Temp"
CONFIG_DIR: Final[Path] = APP_ROOT / "Configuration"

# AES key files
AES_KEY_FILE: Final[Path] = VARS_DIR / "st_aes.py"
AES_LIB_FILE: Final[Path] = VARS_DIR / "st_aes_lib.ini"

# Network defaults
DEFAULT_PORT: Final[int] = 4040
BUFFER_SIZE: Final[int] = 4096
MAX_CONNECTIONS: Final[int] = 50

# Application info
APP_NAME: Final[str] = "Snitch Python 3.13"
APP_VERSION: Final[str] = "1.0.0"
APP_AUTHOR: Final[str] = "Snitch Team"

# Ensure directories exist
for directory in [LOGS_DIR, DOWNLOADS_DIR, UPLOADS_DIR, PAYLOADS_DIR, TEMP_DIR, CONFIG_DIR]:
    directory.mkdir(exist_ok=True)
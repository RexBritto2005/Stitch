# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13

from __future__ import annotations
import base64
from typing import Final

aes_encoded: Final[str] = 'T3VOR2FybEowS2V6MmdTU2Fjc1YycHU5MnAwa25wR0c='
aes_abbrev: Final[str] = ''.join([
    aes_encoded[21], aes_encoded[0], aes_encoded[1], aes_encoded[43], aes_encoded[5],
    aes_encoded[13], aes_encoded[7], aes_encoded[24], aes_encoded[31],
    aes_encoded[35], aes_encoded[16], aes_encoded[39], aes_encoded[28]
])
secret: Final[bytes] = base64.b64decode(aes_encoded)
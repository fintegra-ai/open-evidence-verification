# SPDX-License-Identifier: Apache-2.0

"""Deterministic SHA-256 hashing and digest formatting for OEVP.

All digests in OEVP are represented with an explicit algorithm prefix:
    sha256:<64 lowercase hex characters>
"""

from __future__ import annotations

import hashlib
import re

DIGEST_REGEX = re.compile(r"^sha256:[0-9a-f]{64}$")


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 digest of bytes and return formatted as 'sha256:<hex>'."""
    hex_digest = hashlib.sha256(data).hexdigest().lower()
    return f"sha256:{hex_digest}"


def is_valid_digest(digest: str) -> bool:
    """Check whether a digest string adheres to the 'sha256:<64 hex>' format."""
    return bool(DIGEST_REGEX.match(digest))

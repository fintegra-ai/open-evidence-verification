"""Deterministic SHA-256 hashing and digest formatting for OEVP.

All digests in OEVP are represented with an explicit algorithm prefix:
    sha256:<64 lowercase hex characters>
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import BinaryIO

DIGEST_REGEX = re.compile(r"^sha256:[0-9a-f]{64}$")


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 digest of bytes and return formatted as 'sha256:<hex>'."""
    hex_digest = hashlib.sha256(data).hexdigest().lower()
    return f"sha256:{hex_digest}"


def sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    """Compute SHA-256 digest of a readable binary stream and return 'sha256:<hex>'."""
    hasher = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        hasher.update(chunk)
    return f"sha256:{hasher.hexdigest().lower()}"


def sha256_file(path: str | Path, chunk_size: int = 65536) -> str:
    """Compute SHA-256 digest of a file path and return 'sha256:<hex>'."""
    with open(path, "rb") as f:
        return sha256_stream(f, chunk_size=chunk_size)


def is_valid_digest(digest: str) -> bool:
    """Check whether a digest string adheres to the 'sha256:<64 hex>' format."""
    return bool(DIGEST_REGEX.match(digest))

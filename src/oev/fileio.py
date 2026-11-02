# SPDX-License-Identifier: Apache-2.0
"""Bounded local input reads and decision-pack path containment."""

from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_PACK_MEMBER_BYTES = 64 * 1024 * 1024
MAX_PACK_ENTRIES = 10_000


def read_bounded_file(path: str | Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    target = Path(path)
    metadata = target.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Input must be a regular file: {target}")
    if metadata.st_size > limit:
        raise ValueError(f"Input exceeds {limit}-byte size limit: {target}")
    with target.open("rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError(f"Input must be a regular file: {target}")
        body = handle.read(limit + 1)
    if len(body) > limit:
        raise ValueError(f"Input exceeds {limit}-byte size limit: {target}")
    return body


def pack_member_path(root: Path, name: str) -> Path:
    parts = name.split("/")
    if (
        not name
        or len(name) > 512
        or "\x00" in name
        or "\\" in name
        or ":" in name
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ValueError(f"Unsafe pack member path: {name!r}")
    if root.is_symlink():
        raise ValueError("Pack root must not be a symlink")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Symlink in pack member path: {name!r}")
    if root.resolve() not in current.resolve().parents:
        raise ValueError(f"Pack member escapes root: {name!r}")
    return current

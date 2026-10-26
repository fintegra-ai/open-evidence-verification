# SPDX-License-Identifier: Apache-2.0

"""Safe ZIP transport for decision evidence packs (oev-decision-pack/0.2).

Packs are a directory format; ZIP is only a transport envelope. The rules here
exist because a ZIP is untrusted input the moment it changes hands:

- Validate everything before extracting anything: a malicious archive must
  never leave partially-extracted files behind, inside or outside the target.
- Reject path traversal (absolute paths, ``..`` segments, backslashes, drive
  letters) — zip-slip must fail closed before any filesystem write.
- Reject duplicate entry names: two members claiming the same path is either
  corruption or an attempt to shadow a verified file with a different one.
- Reject encrypted entries and enforce per-entry and total size bounds so a
  small archive cannot exhaust memory (decompression bomb).
- ``create_pack_archive`` writes a deterministic archive (sorted entries, fixed
  metadata) so archive bytes are reproducible and diffable.

After extraction, run ``oev.decision_pack.verify_pack`` on the target
directory; extraction safety and pack integrity are independent properties.
"""

from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_ENTRIES = 10_000
MAX_ENTRY_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 512 * 1024 * 1024

# zipfile always presents entry names with forward slashes, but a hostile
# writer can embed backslashes or drive letters that some extractors resolve.
ENTRY_NAME_FORBIDDEN_CHARS = set('\\:<>|"*?')


class PackArchiveError(ValueError):
    """Raised when a pack archive is malformed, unsafe, or exceeds bounds."""


def _validate_entry_name(name: str) -> None:
    """Reject entry names that could escape the extraction root."""
    if not name:
        raise PackArchiveError("Archive contains an empty entry name")
    if any(ch in ENTRY_NAME_FORBIDDEN_CHARS for ch in name):
        raise PackArchiveError(f"Archive entry uses a forbidden character: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or name.startswith("/"):
        raise PackArchiveError(f"Archive entry has an absolute path: {name!r}")
    parts = name.split("/")
    if ".." in parts or "." in parts:
        raise PackArchiveError(f"Archive entry traverses outside the root: {name!r}")


def create_pack_archive(pack_dir: str | Path, zip_path: str | Path) -> list[str]:
    """Write a deterministic ZIP of the pack directory; returns entry names.

    Entries are the pack files in sorted relative-path order with fixed
    metadata (timestamp, attributes, deflate level), so two archives of the
    same pack bytes are byte-identical.
    """

    pack_dir = Path(pack_dir)
    if not pack_dir.is_dir():
        raise PackArchiveError(f"Pack directory not found: {pack_dir}")

    files = sorted(p for p in pack_dir.rglob("*") if p.is_file())
    if not files:
        raise PackArchiveError(f"Pack directory contains no files: {pack_dir}")
    if len(files) > MAX_ARCHIVE_ENTRIES:
        raise PackArchiveError(
            f"Pack has {len(files)} files, exceeding the archive entry limit {MAX_ARCHIVE_ENTRIES}"
        )

    entries: list[str] = []
    total = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file_path in files:
            rel = file_path.relative_to(pack_dir).as_posix()
            _validate_entry_name(rel)
            body = file_path.read_bytes()
            total += len(body)
            if len(body) > MAX_ENTRY_UNCOMPRESSED_BYTES:
                raise PackArchiveError(f"Pack file exceeds entry size bound: {rel}")
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise PackArchiveError("Pack exceeds total archive size bound")
            info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, body)
            entries.append(rel)
    return entries


def inspect_pack_archive(zip_path: str | Path) -> list[str]:
    """Validate an archive without extracting; returns safe entry names.

    Raises PackArchiveError on traversal names, duplicate members, encrypted
    entries, or bound violations. Performs no filesystem writes.
    """

    zip_path = Path(zip_path)
    if not zip_path.is_file():
        raise PackArchiveError(f"Archive file not found: {zip_path}")
    if zip_path.stat().st_size > MAX_ARCHIVE_FILE_BYTES:
        raise PackArchiveError("Archive file exceeds the size bound")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos: list[zipfile.ZipInfo] = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise PackArchiveError(f"Archive is not a valid ZIP file: {exc}") from exc

    if not infos:
        raise PackArchiveError("Archive is empty")
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise PackArchiveError(
            f"Archive has {len(infos)} entries, exceeding the limit {MAX_ARCHIVE_ENTRIES}"
        )

    seen: dict[str, int] = {}
    file_entries: list[str] = []
    total = 0
    for info in infos:
        name = info.filename
        _validate_entry_name(name)
        seen[name] = seen.get(name, 0) + 1
        if seen[name] > 1:
            raise PackArchiveError(f"Archive contains duplicate entry name: {name!r}")
        if info.flag_bits & 0x1:
            raise PackArchiveError(f"Archive entry is encrypted: {name!r}")
        if info.is_dir():
            continue
        if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
            raise PackArchiveError(f"Archive entry exceeds the size bound: {name!r}")
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise PackArchiveError("Archive total uncompressed size exceeds the bound")
        file_entries.append(name)
    return file_entries


def extract_pack_archive(zip_path: str | Path, out_dir: str | Path) -> list[str]:
    """Safely extract a pack archive into out_dir; returns extracted file names.

    The whole archive is validated first (inspect_pack_archive); only after
    every entry passes does any file get written, and each write target is
    re-checked to resolve inside out_dir (defense in depth).
    """

    out_dir = Path(out_dir)
    entries = inspect_pack_archive(zip_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    root = out_dir.resolve()
    extracted: list[str] = []
    with zipfile.ZipFile(Path(zip_path), "r") as zf:
        for name in entries:
            target = (out_dir / name).resolve()
            if root != target and root not in target.parents:
                raise PackArchiveError(f"Resolved path escapes the extraction root: {name!r}")
            data: bytes = zf.read(name)
            if len(data) > MAX_ENTRY_UNCOMPRESSED_BYTES:
                raise PackArchiveError(f"Decompressed entry exceeds the size bound: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            extracted.append(name)
    return extracted

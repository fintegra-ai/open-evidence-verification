"""Archive failures must not overwrite files or leave a partial extraction."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from oev.pack_archive import PackArchiveError, extract_pack_archive, inspect_pack_archive


def make_zip(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for name in names:
            zf.writestr(name, b"payload-" + name.encode())
    return path


def test_late_crc_failure_leaves_destination_untouched(tmp_path: Path) -> None:
    source = make_zip(tmp_path / "bad.zip", ["first.txt", "last.txt"])
    body = bytearray(source.read_bytes())
    body[body.index(b"payload-last.txt")] ^= 1
    source.write_bytes(body)
    out = tmp_path / "out"
    with pytest.raises(PackArchiveError, match="unreadable"):
        extract_pack_archive(source, out)
    assert not out.exists()


@pytest.mark.parametrize("names", [["first.txt", "dir//last.txt"], ["a", "a/b"]])
def test_alias_or_path_collision_leaves_no_files(tmp_path: Path, names: list[str]) -> None:
    source = make_zip(tmp_path / "bad.zip", names)
    out = tmp_path / "out"
    with pytest.raises(PackArchiveError):
        extract_pack_archive(source, out)
    assert not out.exists()


def test_existing_member_not_overwritten(tmp_path: Path) -> None:
    source = make_zip(tmp_path / "bad.zip", ["first.txt", "last.txt"])
    out = tmp_path / "out"
    out.mkdir()
    (out / "last.txt").write_bytes(b"preserve")
    with pytest.raises(PackArchiveError, match="already exists"):
        extract_pack_archive(source, out)
    assert (out / "last.txt").read_bytes() == b"preserve"
    assert not (out / "first.txt").exists()


def test_symlink_zip_member_rejected(tmp_path: Path) -> None:
    source = tmp_path / "bad.zip"
    with zipfile.ZipFile(source, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "outside")
    with pytest.raises(PackArchiveError, match="symlink"):
        inspect_pack_archive(source)


def test_permanent_archive_regression_vectors(tmp_path: Path) -> None:
    import json

    corpus = Path(__file__).resolve().parents[1] / "conformance" / "archive-regressions"
    for case in json.loads((corpus / "expected.json").read_text())["cases"]:
        out = tmp_path / case["archive"]
        with pytest.raises(PackArchiveError):
            extract_pack_archive(corpus / case["archive"], out)
        assert out.exists() is case["destination_created"]


@pytest.mark.parametrize(
    "names",
    [
        ["First.txt", "first.txt"],
        ["café.txt", "café.txt"],
        ["A", "a/b"],
    ],
)
def test_portable_name_collisions_refused_before_writes(tmp_path: Path, names: list[str]) -> None:
    source = make_zip(tmp_path / "bad.zip", names)
    out = tmp_path / "out"
    with pytest.raises(PackArchiveError):
        extract_pack_archive(source, out)
    assert not out.exists()

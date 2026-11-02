"""Regenerate permanent negative archive vectors; no private data or keys."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "archive-regressions"


def make_archive(names: list[str]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as zf:
        for name in names:
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            zf.writestr(info, b"payload-" + name.encode())
    return stream.getvalue()


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    late_crc = bytearray(make_archive(["first.txt", "last.txt"]))
    late_crc[late_crc.index(b"payload-last.txt")] ^= 1
    cases = {
        "late-crc": bytes(late_crc),
        "empty-segment": make_archive(["first.txt", "dir//last.txt"]),
        "path-collision": make_archive(["a", "a/b"]),
        "case-alias": make_archive(["First.txt", "first.txt"]),
        "unicode-alias": make_archive(["caf\u00e9.txt", "cafe\u0301.txt"]),
    }
    for name, body in cases.items():
        (ROOT / f"{name}.zip").write_bytes(body)
    (ROOT / "expected.json").write_text(
        json.dumps(
            {
                "format": "oev-archive-regressions/0.1",
                "cases": [
                    {
                        "archive": f"{name}.zip",
                        "error": "PackArchiveError",
                        "destination_created": False,
                    }
                    for name in cases
                ],
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()

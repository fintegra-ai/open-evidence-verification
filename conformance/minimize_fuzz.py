# SPDX-License-Identifier: Apache-2.0

"""Minimize a fuzz finding against an archive-verifier command and emit a
conformance-vector DRAFT (Faz C rule: no fuzz issue closes without a vector).

Given a crashing input archive and a verifier command, the tool:

1. records the failure signature (exit code) on the original input;
2. greedily minimizes the archive at member level — a member is dropped when
   the verifier still fails the same way without it (large inputs shrink
   fast; the survivor set is the essential trigger);
3. writes the minimized archive plus a vector DRAFT into the output
   directory.

The draft is deliberately not a runnable vector: wiring the minimized input
into a real ``action`` with expected values is the developer's job, but the
draft carries the captured failure (exit code, stderr tail) so nothing has
to be reconstructed from memory.

Usage::

    python conformance/minimize_fuzz.py --input crash.zip \\
        --verifier "./my-verifier {input}" --out-dir drafts/my-finding

Exit codes: 0 = minimized and draft emitted; 2 = failure not reproducible
on the original input (nothing written); 1 = internal error.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

SUBPROCESS_TIMEOUT_SECONDS = 120
_FIXED_DATE = (1980, 1, 1, 0, 0, 0)


def _run_verifier(command: str, archive: Path) -> tuple[int | None, str]:
    resolved = [part.replace("{input}", str(archive)) for part in shlex.split(command)]
    try:
        completed = subprocess.run(
            resolved,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"
    return completed.returncode, completed.stderr[-400:]


def _still_fails(
    command: str, members: dict[str, bytes], workdir: Path, signature: int | None
) -> bool:
    candidate = workdir / "candidate.zip"
    _write_zip(candidate, members)
    code, _tail = _run_verifier(command, candidate)
    return code == signature


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=_FIXED_DATE)
            archive.writestr(info, data)


def minimize(
    members: dict[str, bytes], command: str, workdir: Path, signature: int | None
) -> dict[str, bytes]:
    current = dict(members)
    for name in sorted(current, reverse=True):
        candidate = {k: v for k, v in current.items() if k != name}
        if candidate and _still_fails(command, candidate, workdir, signature):
            current = candidate
    return current


def _slug(path: Path) -> str:
    stem = path.stem.lower()
    cleaned = "".join(c if c.isalnum() or c in "-_" else "-" for c in stem).strip("-")
    return cleaned or "fuzz-finding"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="minimize-fuzz", description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, required=True, help="crashing archive")
    parser.add_argument(
        "--verifier",
        required=True,
        help="verifier command template containing {input}; failure = nonzero exit",
    )
    parser.add_argument(
        "--out-dir", type=Path, required=True, help="directory for the minimized input and draft"
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"Error: input archive not found: {args.input}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        try:
            with zipfile.ZipFile(args.input) as archive:
                members = {info.filename: archive.read(info) for info in archive.infolist()}
        except zipfile.BadZipFile:
            print(f"Error: {args.input} is not a readable ZIP archive", file=sys.stderr)
            return 1

        original_code, original_tail = _run_verifier(args.verifier, args.input)
        if original_code is None:
            print("Error: verifier timed out on the original input", file=sys.stderr)
            return 2
        if original_code == 0:
            print(
                "Error: verifier exits 0 on the original input; nothing to reproduce.",
                file=sys.stderr,
            )
            return 2

        minimized = minimize(members, args.verifier, workdir, original_code)

        args.out_dir.mkdir(parents=True, exist_ok=True)
        minimized_path = args.out_dir / "minimized.zip"
        _write_zip(minimized_path, minimized)

        final_code, final_tail = _run_verifier(args.verifier, minimized_path)
        draft = {
            "vector_id": _slug(args.input),
            "status": "draft",
            "spec": "OEVP-1.0-draft",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_input": str(args.input),
            "verifier_command": args.verifier,
            "failure_signature": {
                "exit_code": final_code,
                "stderr_tail": final_tail if final_code != 0 else original_tail,
            },
            "minimized_member_count": len(minimized),
            "original_member_count": len(members),
            "note": "Draft only: wire the minimized input into a real vector action with expected values before promoting.",
        }
        (args.out_dir / "input.json").write_text(
            json.dumps(draft, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "minimized_members": len(minimized),
                    "original_members": len(members),
                    "still_fails": final_code != 0,
                    "out_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

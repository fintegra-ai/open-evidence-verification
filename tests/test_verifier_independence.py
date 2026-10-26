# SPDX-License-Identifier: Apache-2.0

"""Verifier-independence tests for the decision pack verifier.

Two mechanical guarantees:

1. Import independence — the offline verifier (pack verification, replay
   safety, archive extraction) must not import application or store code, from
   this repository or anywhere else. Verified statically (AST over the
   verifier's transitive module closure) and at runtime (sys.modules after a
   fresh import in a subprocess).
2. Location independence — the verifier must produce identical results on a
   pack copied into a clean directory that contains no application code, run
   through the CLI in a subprocess with that directory as the working
   directory.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
EXAMPLES_DIR = REPO_ROOT / "examples"
EXAMPLE_PACK_DIR = EXAMPLES_DIR / "demo-case-001"
EXAMPLE_KEYS = EXAMPLES_DIR / "demo-case-001.verifier-keys.json"

# Library entry points that constitute "the verifier".
VERIFIER_ENTRY_MODULES = ["decision_pack", "replay", "pack_archive"]

# Application/store code and host applications the verifier must never touch.
FORBIDDEN_TOP_LEVEL = (
    "oept",
    "evidenceos",
    "evidenceos_core",
    "factoring",
    "finance",
    "app",
    "application",
    "store",
    "sqlalchemy",
    "django",
)
# Protocol-internal modules that are NOT part of the offline verifier path
# (CLI plumbing, package adapters, the receipt execution engine).
FORBIDDEN_OEV_SUBMODULES = ("oev.adapters", "oev.cli", "oev.engine", "oev.reverify", "oev.inspect")


def _static_import_closure(entry_modules: list[str]) -> set[str]:
    """Compute the oev-internal import closure of the entry modules via AST."""

    closure: set[str] = set()
    queue: list[str] = list(entry_modules)
    while queue:
        mod = queue.pop()
        if mod in closure:
            continue
        closure.add(mod)
        file = SRC_DIR / "oev" / f"{mod}.py"
        if not file.is_file():
            continue
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            else:
                continue
            for name in names:
                if name == "oev" or name.startswith("oev."):
                    sub = name.split(".", 1)[1] if "." in name else ""
                    if sub and sub not in closure:
                        queue.append(sub)
    return closure


def test_verifier_static_import_closure_is_protocol_only() -> None:
    """No verifier module (transitively) imports application/store code."""

    closure = _static_import_closure(VERIFIER_ENTRY_MODULES)
    assert {"decision_pack", "replay", "pack_archive"} <= closure
    # The closure stays inside the protocol core.
    assert "adapters" not in closure
    assert "cli" not in closure
    assert "engine" not in closure

    for mod in sorted(closure):
        file = SRC_DIR / "oev" / f"{mod}.py"
        assert file.is_file(), f"closure references missing module oev.{mod}"
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".", 1)[0]
                assert top not in FORBIDDEN_TOP_LEVEL, (
                    f"oev.{mod} imports forbidden module '{name}'"
                )
                if name.startswith("oev."):
                    assert name.split("oev.", 1)[1] not in {"adapters", "cli", "engine"}, (
                        f"oev.{mod} imports non-verifier protocol module '{name}'"
                    )


def test_verifier_runtime_imports_no_application_code() -> None:
    """A fresh import of the verifier in a subprocess loads no app/store code."""

    probe = (
        "import json, sys\n"
        "import oev.decision_pack, oev.replay, oev.pack_archive\n"
        "top = sorted({m.split('.')[0] for m in sys.modules})\n"
        "oev_mods = sorted(m for m in sys.modules if m.startswith('oev.'))\n"
        "print(json.dumps({'top': top, 'oev': oev_mods}))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(SRC_DIR))
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    loaded = json.loads(completed.stdout)

    for name in loaded["top"]:
        assert name not in FORBIDDEN_TOP_LEVEL, f"verifier import loaded '{name}'"
    for name in loaded["oev"]:
        assert not name.startswith(FORBIDDEN_OEV_SUBMODULES), (
            f"verifier import pulled in non-verifier module '{name}'"
        )
    # The verifier entry points and their core dependencies did load.
    for expected in ("oev.decision_pack", "oev.replay", "oev.pack_archive", "oev.trust"):
        assert expected in loaded["oev"]


def test_verifier_works_on_clean_directory_copy(tmp_path: Path) -> None:
    """Verify + replay a pack in a clean directory containing no app code.

    The clean directory holds only the copied pack and the trust roots; the
    verifier runs as a subprocess with that directory as cwd, so any reliance
    on repository layout or application code would fail here.
    """

    clean = tmp_path / "clean-room"
    clean.mkdir()
    pack_dir = clean / "pack"
    pack_dir.mkdir()

    # Directory copy of the pack only (shutil.copytree also copies subdirs).
    for src in sorted(EXAMPLE_PACK_DIR.rglob("*")):
        rel = src.relative_to(EXAMPLE_PACK_DIR)
        if src.is_dir():
            (pack_dir / rel).mkdir(parents=True, exist_ok=True)
        else:
            target = pack_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(src.read_bytes())
    (clean / "verifier-keys.json").write_bytes(EXAMPLE_KEYS.read_bytes())

    # The clean room contains exactly the pack and the keys — no app code.
    assert sorted(p.relative_to(clean).as_posix() for p in clean.rglob("*") if p.is_file()) == [
        "pack/artifacts/maintenance-policy.txt",
        "pack/artifacts/sensor-export.csv",
        "pack/case.json",
        "pack/facts.json",
        "pack/findings.json",
        "pack/manifest.dsse.json",
        "pack/manifest.json",
        "pack/review_actions.json",
        "pack/rule_runs.json",
        "pack/snapshot_context.json",
        "pack/timeline.json",
        "verifier-keys.json",
    ]

    manifest_before = (pack_dir / "manifest.json").read_bytes()
    env = dict(os.environ, PYTHONPATH=str(SRC_DIR))

    verify_run = subprocess.run(
        [
            sys.executable,
            "-m",
            "oev.cli",
            "pack",
            "verify",
            "pack",
            "--verifier-keys",
            "verifier-keys.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=clean,
        env=env,
        check=False,
    )
    assert verify_run.returncode == 0, verify_run.stderr
    report = json.loads(verify_run.stdout)
    assert report["overall"] == "PACK_VALID"
    assert report["is_trusted_signer"] is True

    replay_run = subprocess.run(
        [
            sys.executable,
            "-m",
            "oev.cli",
            "pack",
            "replay",
            "pack",
            "--verifier-keys",
            "verifier-keys.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=clean,
        env=env,
        check=False,
    )
    assert replay_run.returncode == 0, replay_run.stderr
    replay = json.loads(replay_run.stdout)
    assert replay["replay_status"] == "REPLAY_OK"
    assert replay["eligible_fact_ids"] == ["fact-001", "fact-002", "fact-003"]

    # Verification is read-only: the pack bytes are untouched.
    assert (pack_dir / "manifest.json").read_bytes() == manifest_before


def test_clean_directory_replay_refuses_tampered_copy(tmp_path: Path) -> None:
    """The same clean-room run must fail closed on a tampered copy."""

    clean = tmp_path / "clean-room"
    clean.mkdir()
    pack_dir = clean / "pack"
    pack_dir.mkdir()
    for src in sorted(EXAMPLE_PACK_DIR.rglob("*")):
        rel = src.relative_to(EXAMPLE_PACK_DIR)
        if src.is_dir():
            (pack_dir / rel).mkdir(parents=True, exist_ok=True)
        else:
            target = pack_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(src.read_bytes())
    (clean / "verifier-keys.json").write_bytes(EXAMPLE_KEYS.read_bytes())

    facts_path = pack_dir / "facts.json"
    facts = json.loads(facts_path.read_bytes())
    facts["facts"][0]["value"] = "999.9"  # tamper with a recorded reading
    from oev.canonical import canonicalize_json

    facts_path.write_bytes(canonicalize_json(facts))

    env = dict(os.environ, PYTHONPATH=str(SRC_DIR))
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "oev.cli",
            "pack",
            "verify",
            "pack",
            "--verifier-keys",
            "verifier-keys.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=clean,
        env=env,
        check=False,
    )
    assert run.returncode == 1
    report = json.loads(run.stdout)
    assert report["overall"] == "PACK_INVALID"

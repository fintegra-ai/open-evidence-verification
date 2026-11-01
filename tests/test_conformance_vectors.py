# SPDX-License-Identifier: Apache-2.0

"""Tests for the language-independent conformance vector runner (Faz C)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import zipfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from oev.adapters.oept import is_oept_available

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "conformance" / "run_vectors.py"
VECTORS_DIR = REPO_ROOT / "conformance" / "vectors"

# The active vectors verify OEPT bundles through the OEVP adapter, so the
# whole module needs OEPT. The CI integration job installs OEPT and asserts
# importability, so these tests run (instead of skip) there.
pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")


def _run_runner(*args: str) -> tuple[int, dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(RUNNER), *args],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    report_path = Path(args[args.index("--report") + 1])
    return completed.returncode, json.loads(report_path.read_text(encoding="utf-8"))


def test_builtin_reference_verifier_passes_all_active_vectors(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    code, report = _run_runner(
        "run",
        "--verifier",
        "builtin",
        "--report",
        str(report_path),
    )
    assert code == 0, [r for r in report["results"] if r.get("passed") is False]
    assert report["summary"]["failed"] == 0
    assert report["summary"]["passed"] == 12
    assert report["summary"]["skipped_planned"] == 2
    assert report["vector_set"] == "oev-conformance-vectors"


def test_external_verifier_with_wrong_answers_fails_closed(tmp_path: Path) -> None:
    stub = tmp_path / "wrong_verifier.py"
    stub.write_text(
        "import json, sys\nvector = json.load(open(sys.argv[1]))\nprint(json.dumps({'vector_id': vector['vector_id'], 'exit_code': 99, 'result': {}}))",
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"
    code, report = _run_runner(
        "run",
        "--verifier",
        f"{sys.executable} {stub} {{input}}",
        "--report",
        str(report_path),
    )
    assert code == 1
    assert report["summary"]["failed"] == 12
    assert report["summary"]["passed"] == 0


def test_comparison_machinery_matches_and_rejects() -> None:
    spec = importlib.util.spec_from_file_location("run_vectors", RUNNER)
    assert spec is not None and spec.loader is not None
    run_vectors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_vectors)

    vector = {"vector_id": "x", "action": "verify"}
    expected = {
        "vector_id": "x",
        "exit_code": 0,
        "asserts": {"overall_result": "TECHNICAL_CHECKS_PASSED"},
    }
    matching = {"exit_code": 0, "result": {"overall_result": "TECHNICAL_CHECKS_PASSED"}}
    assert run_vectors.compare(vector, expected, matching)["passed"] is True

    wrong_exit = {"exit_code": 2, "result": {"overall_result": "TECHNICAL_CHECKS_PASSED"}}
    assert run_vectors.compare(vector, expected, wrong_exit)["passed"] is False

    # checks normalization: observed list of check objects reduces to a map.
    listed = {
        "exit_code": 0,
        "result": {
            "overall_result": "TECHNICAL_CHECKS_PASSED",
            "checks": [{"check_id": "archive_safety", "status": "PASS"}],
        },
    }
    map_expected = {
        "vector_id": "x",
        "exit_code": 0,
        "asserts": {"checks": {"archive_safety": "PASS"}},
    }
    assert run_vectors.compare(vector, map_expected, listed)["passed"] is True


def test_manifest_and_vector_files_are_consistent() -> None:
    manifest = json.loads((VECTORS_DIR / "manifest.json").read_text(encoding="utf-8"))
    ids = [v["id"] for v in manifest["vectors"]]
    assert len(ids) == len(set(ids))
    for entry in manifest["vectors"]:
        directory = VECTORS_DIR / entry["id"]
        assert (directory / "input.json").is_file(), entry["id"]
        if entry["status"] == "active":
            expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
            assert expected["vector_id"] == entry["id"]
            assert isinstance(expected["exit_code"], int)
        else:
            assert not (directory / "expected.json").exists(), (
                f"{entry['id']} planned but has expected.json"
            )


def test_evidence_pack_is_an_oept_bundle_verifiable_by_oevp(tmp_path: Path) -> None:
    from oev.cli import main as cli_main

    report_path = tmp_path / "report.json"
    pack_path = tmp_path / "evidence.oeptbundle.zip"
    code, report = _run_runner(
        "run",
        "--verifier",
        "builtin",
        "--report",
        str(report_path),
        "--evidence-pack",
        str(pack_path),
    )
    assert code == 0
    assert pack_path.is_file()
    assert report["oev_version"] is not None

    with zipfile.ZipFile(pack_path) as archive:
        names = set(archive.namelist())
        assert "evidence/report.json" in names
        assert "evidence/vector-set-manifest.json" in names

    # OEVP verifies the pack as an oept-bundle/0.1 package: structure and
    # member digests bind the exact report bytes (signature not required,
    # so the profile omits application_signature).
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "protocol_version": "oev-profile/0.1",
                "profile_id": "evidence-pack-profile",
                "profile_version": "0.1.0",
                "target_format": "oept-bundle/0.1",
                "required_checks": ["archive_safety", "manifest_structure", "member_digests"],
            }
        ),
        encoding="utf-8",
    )
    buffer = StringIO()
    with redirect_stdout(buffer):
        ret = cli_main(["verify", str(pack_path), "--profile", str(profile)])
    assert ret == 0
    receipt = json.loads(buffer.getvalue().splitlines()[0])
    assert receipt["overall_result"] == "TECHNICAL_CHECKS_PASSED"


def test_minimize_fuzz_shrinks_to_the_essential_trigger(tmp_path: Path) -> None:
    stub = tmp_path / "evil_detector.py"
    stub.write_text(
        (
            "import sys, zipfile\n"
            "names = zipfile.ZipFile(sys.argv[1]).namelist()\n"
            "sys.exit(1 if any('evil' in n for n in names) else 0)\n"
        ),
        encoding="utf-8",
    )
    crash = tmp_path / "crash.zip"
    with zipfile.ZipFile(crash, "w") as archive:
        for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt", "evil-payload.bin"):
            archive.writestr(name, b"data-" + name.encode())

    out_dir = tmp_path / "draft"
    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "conformance" / "minimize_fuzz.py"),
            "--input",
            str(crash),
            "--verifier",
            f"{sys.executable} {stub} {{input}}",
            "--out-dir",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    with zipfile.ZipFile(out_dir / "minimized.zip") as archive:
        assert archive.namelist() == ["evil-payload.bin"]
    draft = json.loads((out_dir / "input.json").read_text(encoding="utf-8"))
    assert draft["status"] == "draft"
    assert draft["failure_signature"]["exit_code"] == 1
    assert draft["original_member_count"] == 6
    assert draft["minimized_member_count"] == 1


def test_minimize_fuzz_refuses_when_nothing_reproduces(tmp_path: Path) -> None:
    stub = tmp_path / "always_ok.py"
    stub.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    crash = tmp_path / "crash.zip"
    with zipfile.ZipFile(crash, "w") as archive:
        archive.writestr("a.txt", b"x")
    out_dir = tmp_path / "draft"
    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "conformance" / "minimize_fuzz.py"),
            "--input",
            str(crash),
            "--verifier",
            f"{sys.executable} {stub} {{input}}",
            "--out-dir",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 2
    assert not (out_dir / "input.json").exists()

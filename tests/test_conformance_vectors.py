# SPDX-License-Identifier: Apache-2.0

"""Tests for the language-independent conformance vector runner (Faz C)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "conformance" / "run_vectors.py"
VECTORS_DIR = REPO_ROOT / "conformance" / "vectors"


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

# SPDX-License-Identifier: Apache-2.0

"""Drive the HEA conformance vectors (hea-01..hea-14) through the runner."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "conformance" / "run_hea_vectors.py"
VECTORS_DIR = REPO_ROOT / "conformance" / "vectors-hea"


def _load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_hea_vectors", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hea_vector_manifest_lists_all_fourteen_vectors() -> None:
    manifest = json.loads((VECTORS_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["vector_set"] == "oev-hea-conformance-vectors"
    assert manifest["version"] == "0.1.0"
    ids = [v["id"] for v in manifest["vectors"]]
    assert ids == [f"hea-{n:02d}" for n in range(1, 15)]
    assert all(v["status"] == "active" for v in manifest["vectors"])
    for vector_id in ids:
        input_doc, expected = _load_runner().load_vector(vector_id)
        assert input_doc["vector_id"] == vector_id
        assert expected["vector_id"] == vector_id
        assert expected["exit_code"] == 0
        assert set(expected["asserts"]) == {"historical_execution", "reason"}


def test_all_hea_vectors_pass(tmp_path: Path) -> None:
    runner = _load_runner()
    report = runner.run_all()
    failures = [v for v in report["vectors"] if not v["passed"]]
    assert failures == [], f"failing HEA vectors: {json.dumps(failures, indent=2)}"
    assert report["passed"] == 14
    assert report["failed"] == 0
    assert report["skipped"] == []


@pytest.mark.parametrize("vector_id", [f"hea-{n:02d}" for n in range(1, 15)])
def test_each_hea_vector_passes(vector_id: str, tmp_path: Path) -> None:
    runner = _load_runner()
    entry = runner.run_vector(vector_id, tmp_path)
    assert entry["passed"], f"{vector_id} failed: {json.dumps(entry, indent=2)}"

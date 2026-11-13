# SPDX-License-Identifier: Apache-2.0

"""HEA verifier independence (HEA design §6.3).

The offline HEA verifier must not import producer or application code:
its transitive import closure stays inside the protocol core, and a fresh
import in a subprocess loads no engine / adapter / replay / CLI module.
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

# The HEA verifier entry point and the protocol-core modules it may use.
HEA_ENTRY_MODULES = ["hea_verifier"]
ALLOWED_OEV_MODULES = {
    "hea_verifier",
    "execution",
    "attestation",
    "execution_log",
    "revocation",
    "trust",
    "signing",
    "dsse",
    "canonical",
    "hashing",
    "schemas",
    "models",
    "receipts",
    "profiles",
    "fileio",
    "__init__",
}

FORBIDDEN_OEV_SUBMODULES = (
    "oev.engine",
    "oev.adapters",
    "oev.replay",
    "oev.cli",
    "oev.inspect",
    "oev.decision_pack",
    "oev.pack_verifier",
    "oev.pack_archive",
    "oev.reverify",
    "oev.witness",
    "oev.witness_worker",
    "oev.hea",
)


def _static_import_closure(entry_modules: list[str]) -> set[str]:
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


def test_hea_verifier_static_import_closure_is_protocol_only() -> None:
    closure = _static_import_closure(HEA_ENTRY_MODULES)
    assert "hea_verifier" in closure
    forbidden = closure - ALLOWED_OEV_MODULES
    assert not forbidden, f"HEA verifier closure pulls in non-core modules: {sorted(forbidden)}"
    for mod in ("engine", "adapters", "replay", "cli", "reverify", "witness", "hea"):
        assert mod not in closure


def test_hea_verifier_runtime_imports_no_producer_code() -> None:
    probe = (
        "import json, sys\n"
        "import oev.hea_verifier\n"
        "oev_mods = sorted(m for m in sys.modules if m.startswith('oev.'))\n"
        "print(json.dumps({'oev': oev_mods}))\n"
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
    for name in loaded["oev"]:
        assert not any(
            name == forbidden or name.startswith(forbidden + ".")
            for forbidden in FORBIDDEN_OEV_SUBMODULES
        ), f"HEA verifier import pulled in producer module '{name}'"
    assert "oev.hea_verifier" in loaded["oev"]
    assert "oev.execution" in loaded["oev"]
    assert "oev.attestation" in loaded["oev"]
    assert "oev.execution_log" in loaded["oev"]


def test_hea_verify_works_on_clean_directory_copy(tmp_path: Path) -> None:
    """Offline HEA verification in a clean directory with no repo code.

    Only the artifacts + trust roots are copied; the verifier runs as a
    subprocess with that directory as cwd.
    """
    bundle_dir = tmp_path / "clean-room"
    bundle_dir.mkdir()
    from oev.canonical import canonicalize_json
    from tests.hea_helpers import build_valid_hea

    (tmp_path / "build").mkdir()
    bundle = build_valid_hea(tmp_path / "build")
    (bundle_dir / "package.bin").write_bytes(bundle["package_bytes"])
    (bundle_dir / "receipt.json").write_bytes(
        canonicalize_json(bundle["receipt"].to_dict(include_digest=True))
    )

    (bundle_dir / "profile.json").write_bytes(canonicalize_json(bundle["profile"].to_dict()))
    attest_dir = bundle_dir / "attestations"
    attest_dir.mkdir()
    for envelope in bundle["attestation_envelopes"]:
        from oev.attestation import parse_attestation_envelope

        payload = parse_attestation_envelope(envelope)
        (attest_dir / f"{payload['check_id']}.dsse.json").write_bytes(canonicalize_json(envelope))
    (bundle_dir / "execution-log.jsonl").write_bytes(bundle["log_jsonl"])
    (bundle_dir / "checkpoint.dsse.json").write_bytes(
        canonicalize_json(bundle["checkpoint_envelope"])
    )
    (bundle_dir / "commitment.dsse.json").write_bytes(
        canonicalize_json(bundle["commitment_envelope"])
    )
    (bundle_dir / "prebinding.json").write_bytes(canonicalize_json(bundle["prebinding"]))
    (bundle_dir / "hea-manifest.json").write_bytes(
        canonicalize_json(
            {
                "inclusion_proofs": bundle["inclusion_proofs"],
                "code_digest": bundle["code_digest"],
            }
        )
    )
    from tests.hea_helpers import write_trust_store_json

    write_trust_store_json(
        bundle_dir / "witness-keys.json",
        [
            {
                "key_id": "wit-1",
                "public_key_pem": bundle["witness_store"].keys[0].public_key_pem.decode(),
                "role": "witness",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-12-31T23:59:59Z",
            }
        ],
    )
    write_trust_store_json(
        bundle_dir / "checkpoint-keys.json",
        [
            {
                "key_id": "cp-1",
                "public_key_pem": bundle["checkpoint_store"].keys[0].public_key_pem.decode(),
                "role": "checkpoint-signer",
                "not_after": "2027-12-31T23:59:59Z",
            }
        ],
    )
    env = dict(os.environ, PYTHONPATH=str(SRC_DIR))
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "oev.cli",
            "hea",
            "verify",
            "package.bin",
            "--receipt",
            "receipt.json",
            "--profile",
            "profile.json",
            "--attestations",
            "attestations",
            "--log",
            "execution-log.jsonl",
            "--checkpoint",
            "checkpoint.dsse.json",
            "--witness-keys",
            "witness-keys.json",
            "--checkpoint-keys",
            "checkpoint-keys.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=bundle_dir,
        env=env,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"

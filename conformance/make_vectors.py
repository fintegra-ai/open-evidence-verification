# SPDX-License-Identifier: Apache-2.0

"""Regenerate conformance/vectors from the byte-stable conformance fixtures.

The vectors are language-independent: each vector references fixture files
(never copies them), and its ``expected.json`` carries only fields that any
verifier can observe (exit code plus a JSON subset). Run from the repository
root::

    python conformance/make_vectors.py
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "conformance" / "fixtures"
VECTORS = REPO / "conformance" / "vectors"


def classify(directory: Path) -> tuple[str, dict, set[str]]:
    expected = json.loads((directory / "expected-result.json").read_text(encoding="utf-8"))
    files = {p.name for p in directory.iterdir() if p.name != "expected-result.json"}
    if "pack-verification-receipt.json" in files:
        return "pack_receipt_verify", expected, files
    if "replay_status" in expected:
        return "pack_replay", expected, files
    if "reverification_result" in expected:
        return "reverify", expected, files
    if "overall_result" in expected:
        return "verify", expected, files
    if "receipt_digest_valid" in expected:
        return "inspect_receipt", expected, files
    if "overall" in expected:
        return "pack_verify", expected, files
    return "pack_archive_extract", expected, files


def inputs_for(action: str, directory: Path, files: set[str]) -> dict[str, str]:
    ref = lambda name: f"conformance/fixtures/{directory.name}/{name}"
    candidates = {
        "package": "package.zip",
        "profile": "profile.json",
        "package_trust_keys": "package-trust-keys.json",
        "receipt": "receipt.dsse.json",
        "verifier_keys": "verifier-trust-keys.json",
        "pack": "pack",
        "pin": "pin.json",
        "pack_receipt": "pack-verification-receipt.json",
        "pack_verifier_keys": "verifier-keys.json",
        "archive": "hostile.zip",
    }
    relevant = {
        "verify": {"package", "profile", "package_trust_keys"},
        "inspect_receipt": {"receipt", "verifier_keys"},
        "reverify": {"package", "profile", "receipt", "package_trust_keys"},
        "pack_replay": {"pack", "pin"},
        "pack_verify": {"pack", "pack_verifier_keys"},
        "pack_receipt_verify": {"pack", "pack_receipt", "pack_verifier_keys"},
        "pack_archive_extract": {"archive"},
    }[action]
    return {
        key: ref(candidates[key])
        for key in relevant
        if candidates[key] in files or (key == "pack" and "pack" in files)
    }


def asserts_for(action: str, expected: dict) -> dict:
    if action == "verify":
        keys = ("overall_result", "checks")
    elif action == "reverify":
        keys = ("reverification_result", "package_digest_match", "profile_digest_match")
    elif action == "inspect_receipt":
        keys = ("receipt_digest_valid", "crypto_valid", "is_trusted_signer")
    elif action == "pack_replay":
        keys = ("replay_status",)
    elif action == "pack_verify":
        keys = ("overall", "signature_state")
    elif action == "pack_receipt_verify":
        # Fixture field names map to the CLI's JSON field names. NOTE:
        # recorded_signature_state is metadata recorded INSIDE the receipt,
        # not observable by the third-party verifier; the observable fields
        # are overall, receipt_digest_valid, pack_binding.
        mapped: dict = {}
        if "receipt_overall" in expected:
            mapped["overall"] = expected["receipt_overall"]
        if "receipt_digest_valid" in expected:
            mapped["receipt_digest_valid"] = expected["receipt_digest_valid"]
        if "pack_binding" in expected:
            mapped["pack_binding"] = expected["pack_binding"]
        return mapped
    else:
        keys = ()
    return {k: expected[k] for k in keys if k in expected}


def exit_for(action: str, expected: dict) -> int | None:
    if action == "verify":
        return 0 if expected.get("overall_result") == "TECHNICAL_CHECKS_PASSED" else 2
    if action == "reverify":
        return 0 if expected.get("reverification_result") == "MATCH" else 2
    if action == "inspect_receipt":
        return 0 if expected.get("receipt_digest_valid") else 1
    if action == "pack_replay":
        return {"REPLAY_OK": 0, "PACK_INVALID": 1}.get(expected.get("replay_status"), 2)
    if action == "pack_verify":
        if expected.get("overall") != "PACK_VALID":
            return 1
        if expected.get("signature_state") == "SIGNATURE_INVALID":
            return 2
        return 0
    if action == "pack_receipt_verify":
        if expected.get("receipt_overall") != "RECEIPT_VALID" or not expected.get(
            "receipt_digest_valid"
        ):
            return 1
        if expected.get("recorded_signature_state") not in (None, "SIGNATURE_VALID"):
            return 2
        return 0
    return None


def main() -> None:
    if VECTORS.exists():
        shutil.rmtree(VECTORS)
    VECTORS.mkdir(parents=True)
    active_entries: list[dict] = []
    planned_entries: list[dict] = []
    for directory in sorted(FIXTURES.iterdir()):
        if not directory.is_dir():
            continue
        action, expected, files = classify(directory)
        status = "active" if action != "pack_archive_extract" else "planned"
        vector = {
            "vector_id": directory.name,
            "action": action,
            "status": status,
            "spec": "OEVP-1.0-draft",
            "source_fixture": f"conformance/fixtures/{directory.name}",
            "inputs": inputs_for(action, directory, files),
            "note": expected.get("note", ""),
        }
        target = VECTORS / directory.name
        target.mkdir()
        (target / "input.json").write_text(
            json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        if status == "active":
            outcome = {
                "vector_id": directory.name,
                "exit_code": exit_for(action, expected),
                "asserts": asserts_for(action, expected),
            }
            (target / "expected.json").write_text(
                json.dumps(outcome, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            active_entries.append({"id": directory.name, "action": action, "status": "active"})
        else:
            planned_entries.append(
                {
                    "id": directory.name,
                    "action": action,
                    "status": "planned",
                    "reason": "pack-archive extraction has no CLI contract yet; runner support is C+ work",
                }
            )
    manifest = {
        "vector_set": "oev-conformance-vectors",
        "version": "0.1.0",
        "spec_target": "spec/OEVP-1.0-draft.md",
        "generated_from": "conformance/fixtures (byte-stable, referenced not copied)",
        "runner": "conformance/run_vectors.py",
        "vectors": active_entries + planned_entries,
    }
    (VECTORS / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"active={len(active_entries)} planned={len(planned_entries)}")


if __name__ == "__main__":
    main()

# SPDX-License-Identifier: Apache-2.0

"""Generate the OEVP conformance fixtures deterministically.

Fixtures 01-06 exercise the package verification engine and are copied from the
OEPT conformance corpus. Set OEPT_FIXTURES_DIR to the location of the OEPT
repository's ``conformance/fixtures`` directory when regenerating; the default
assumes the OEPT checkout sits next to this repository.

Fixtures 07-14 exercise the decision pack surface (offline verifier, portable
receipt, replay gate, archive transport) and are generated from the committed
neutral example pack ``examples/demo-case-001``; they require only the OEVP
core, never the OEPT adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from oev.canonical import canonicalize_json
from oev.engine import execute_verification
from oev.models import VerificationProfile
from oev.signing import generate_ed25519_keypair

ROOT = Path(__file__).resolve().parent
FIXTURES_DIR = ROOT / "fixtures"
_DEFAULT_OEPT_DIR = ROOT.parent / "open-evidence-provenance" / "conformance" / "fixtures"
OEPT_DIR = Path(os.environ.get("OEPT_FIXTURES_DIR", _DEFAULT_OEPT_DIR))
EXAMPLES_DIR = ROOT.parent / "examples"
EXAMPLE_PACK_DIR = EXAMPLES_DIR / "demo-case-001"
EXAMPLE_KEYS = EXAMPLES_DIR / "demo-case-001.verifier-keys.json"

# Deterministic receipt identity for fixture 10 (uuid4()/now() would not reproduce).
FIXED_RECEIPT_ID = "00000000-0000-4000-8000-000000000010"
FIXED_VERIFIED_AT = "2026-10-01T12:00:00Z"


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # Deterministic verifier test keypair
    priv_pem, pub_pem = generate_ed25519_keypair()
    verifier_trust_keys = [
        {"key_id": "test-verifier-2026", "public_key_pem": pub_pem.decode("utf-8")}
    ]

    # Common strict profile (requires application signature)
    strict_profile = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "strict-conformance-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": [
            "archive_safety",
            "manifest_structure",
            "member_digests",
            "application_signature",
        ],
        "optional_checks": [],
        "parameters": {},
        "description": "Strict profile requiring safe archive, manifest, member digests, and application signature",
    }

    # -------------------------------------------------------------
    # FIXTURE 01: 01-valid-oept-pass
    # -------------------------------------------------------------
    f1_dir = FIXTURES_DIR / "01-valid-oept-pass"
    f1_dir.mkdir(exist_ok=True)
    bundle_01_src = OEPT_DIR / "02-valid-signed" / "bundle.zip"
    bundle_01_keys_src = OEPT_DIR / "02-valid-signed" / "trust-keys.json"

    shutil.copy(bundle_01_src, f1_dir / "package.zip")
    shutil.copy(bundle_01_keys_src, f1_dir / "package-trust-keys.json")
    (f1_dir / "profile.json").write_text(
        canonicalize_json(strict_profile).decode("utf-8"), encoding="utf-8"
    )
    (f1_dir / "verifier-trust-keys.json").write_text(
        canonicalize_json(verifier_trust_keys).decode("utf-8"), encoding="utf-8"
    )

    with open(f1_dir / "package-trust-keys.json") as f:
        pkg_keys = json.load(f)

    prof_obj = VerificationProfile.from_dict(strict_profile)
    _receipt_01, envelope_01 = execute_verification(
        package_bytes=(f1_dir / "package.zip").read_bytes(),
        profile=prof_obj,
        package_trust_keys=pkg_keys,
        private_key_pem=priv_pem,
        signer_key_id="test-verifier-2026",
    )
    (f1_dir / "receipt.dsse.json").write_text(
        canonicalize_json(envelope_01).decode("utf-8"), encoding="utf-8"
    )
    (f1_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "TECHNICAL_CHECKS_PASSED",
                "receipt_signature_trusted": True,
                "trusted_verifier_key_id": "test-verifier-2026",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "PASS",
                    "application_signature": "PASS",
                },
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 02: 02-tampered-package
    # -------------------------------------------------------------
    f2_dir = FIXTURES_DIR / "02-tampered-package"
    f2_dir.mkdir(exist_ok=True)
    bundle_02_src = OEPT_DIR / "03-tampered-artifact" / "bundle.zip"
    shutil.copy(bundle_02_src, f2_dir / "package.zip")

    profile_02 = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "integrity-check-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": [
            "archive_safety",
            "manifest_structure",
            "member_digests",
        ],
    }
    (f2_dir / "profile.json").write_text(
        canonicalize_json(profile_02).decode("utf-8"), encoding="utf-8"
    )
    (f2_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "TECHNICAL_CHECKS_FAILED",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "FAIL",
                },
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 03: 03-required-signature-unsatisfied
    # -------------------------------------------------------------
    f3_dir = FIXTURES_DIR / "03-required-signature-unsatisfied"
    f3_dir.mkdir(exist_ok=True)
    bundle_03_src = OEPT_DIR / "01-valid-unsigned" / "bundle.zip"
    shutil.copy(bundle_03_src, f3_dir / "package.zip")
    (f3_dir / "profile.json").write_text(
        canonicalize_json(strict_profile).decode("utf-8"), encoding="utf-8"
    )
    (f3_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "PROFILE_UNSATISFIED",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "PASS",
                    "application_signature": "UNVERIFIED",
                },
                "note": "Required check 'application_signature' was UNVERIFIED on unsigned package",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 04: 04-tampered-receipt
    # -------------------------------------------------------------
    f4_dir = FIXTURES_DIR / "04-tampered-receipt"
    f4_dir.mkdir(exist_ok=True)
    shutil.copy(f1_dir / "verifier-trust-keys.json", f4_dir / "verifier-trust-keys.json")

    # Take receipt 01 and mutate its inner payload
    envelope_data = json.loads((f1_dir / "receipt.dsse.json").read_text(encoding="utf-8"))
    payload_bytes = base64.b64decode(envelope_data["payload"])
    receipt_data = json.loads(payload_bytes.decode("utf-8"))
    # Tamper with the check result inside payload
    receipt_data["checks"][0]["status"] = "FAIL"
    tampered_payload_bytes = canonicalize_json(receipt_data)
    envelope_data["payload"] = base64.b64encode(tampered_payload_bytes).decode("ascii")

    (f4_dir / "receipt.dsse.json").write_text(
        canonicalize_json(envelope_data).decode("utf-8"), encoding="utf-8"
    )
    (f4_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "is_trusted_signer": False,
                "crypto_valid": False,
                "receipt_digest_valid": False,
                "note": "Tampered receipt payload must fail DSSE signature verification and self-digest check",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 05: 05-reverify-package-mismatch
    # -------------------------------------------------------------
    f5_dir = FIXTURES_DIR / "05-reverify-package-mismatch"
    f5_dir.mkdir(exist_ok=True)
    shutil.copy(f1_dir / "receipt.dsse.json", f5_dir / "receipt.dsse.json")
    shutil.copy(f1_dir / "profile.json", f5_dir / "profile.json")
    # Provide a different package (unsigned bundle instead of signed bundle)
    shutil.copy(bundle_03_src, f5_dir / "package.zip")
    (f5_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "reverification_result": "MISMATCH",
                "package_digest_match": False,
                "note": "Package digest mismatch between historic receipt and fresh package bytes",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 06: 06-signature-invalid
    # -------------------------------------------------------------
    f6_dir = FIXTURES_DIR / "06-signature-invalid"
    f6_dir.mkdir(exist_ok=True)
    shutil.copy(OEPT_DIR / "06-signature-invalid" / "bundle.zip", f6_dir / "package.zip")
    # Trust keys carry the key the bundle claims, so the failure is genuinely
    # cryptographic (invalid signature), not missing trust context.
    shutil.copy(
        OEPT_DIR / "06-signature-invalid" / "trust-keys.json", f6_dir / "package-trust-keys.json"
    )
    (f6_dir / "profile.json").write_text(
        canonicalize_json(strict_profile).decode("utf-8"), encoding="utf-8"
    )
    with open(f6_dir / "package-trust-keys.json") as f:
        pkg_keys_06 = json.load(f)
    receipt_06, _ = execute_verification(
        package_bytes=(f6_dir / "package.zip").read_bytes(),
        profile=VerificationProfile.from_dict(strict_profile),
        package_trust_keys=pkg_keys_06,
    )
    assert receipt_06.overall_result == "TECHNICAL_CHECKS_FAILED"
    (f6_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "TECHNICAL_CHECKS_FAILED",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "PASS",
                    "application_signature": "FAIL",
                },
                "note": "Bundle carries a corrupted application signature; signature check FAILs "
                "(distinct from UNVERIFIED on unsigned bundles)",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    print("All 6 OEPT package conformance fixtures generated successfully.")


# ---------------------------------------------------------------------------
# Fixtures 07-14: decision pack surface, generated from demo-case-001
# ---------------------------------------------------------------------------


def _copy_example_pack(dest: Path) -> None:
    """Copy the committed example pack bytes into a fixture (deterministic)."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(EXAMPLE_PACK_DIR, dest)


def _rewrite_members_and_manifest(
    pack_dir: Path, mutations: dict[str, Callable[[dict[str, Any]], dict[str, Any]]]
) -> None:
    """Rewrite JSON members and rebuild the manifest self-consistently.

    Simulates the strongest attacker: member bytes change AND the manifest is
    rebuilt coherently (digests, sizes, pack_digest), so only an external pin
    or a signature can detect it. The stale DSSE envelope is removed because a
    rebuilt manifest can no longer be bound by the old payload.
    """
    from oev.pack_verifier import compute_manifest_self_digest

    for member_name, mutate in mutations.items():
        doc = json.loads((pack_dir / member_name).read_bytes())
        body = canonicalize_json(mutate(doc))
        (pack_dir / member_name).write_bytes(body)

    manifest_path = pack_dir / "manifest.json"
    manifest: dict[str, Any] = json.loads(manifest_path.read_bytes())
    for member in manifest["members"]:
        if member["path"] in mutations:
            body = (pack_dir / member["path"]).read_bytes()
            member["size_bytes"] = len(body)
            member["sha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
    manifest.pop("pack_digest", None)
    manifest["pack_digest"] = compute_manifest_self_digest(manifest)
    manifest_path.write_bytes(canonicalize_json(manifest))
    envelope = pack_dir / "manifest.dsse.json"
    if envelope.is_file():
        envelope.unlink()


def _late_reading_fact() -> dict[str, Any]:
    return {
        "fact_id": "fact-901",
        "key": "sensor.reading_after_capture",
        "value": "99.9",
        "value_type": "decimal_string",
        "source": "sensor-feed-A",
        "observed_at": "2026-10-01T09:00:00Z",
        "snapshot_source_id": "sensor-export-2026-10-01",
    }


def _late_reading_run() -> dict[str, Any]:
    from oev.decision_pack import compute_rule_digest

    rule = {
        "rule_id": "late-reading-check",
        "rule_version": "1.0.0",
        "description": "Synthetic rule consuming a reading observed after the snapshot capture.",
        "condition": {
            "op": "eq",
            "args": [{"fact": "sensor.reading_after_capture"}, {"const": True}],
        },
    }
    return {
        "run_id": "run-901",
        "rule": {**rule, "rule_digest": compute_rule_digest(rule)},
        "inputs": ["fact-901"],
        "outcome": "TRIGGERED",
        "executed_at": "2026-10-01T09:05:00Z",
        "executed_by": "oev-demo-rules/0.2",
        "detail": "Recorded run consuming evidence observed after the snapshot capture.",
    }


def _write_expected(fixture_dir: Path, expected: dict[str, Any]) -> None:
    (fixture_dir / "expected-result.json").write_bytes(canonicalize_json(expected))


def _deterministic_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    """Write a ZIP with fixed metadata so the committed bytes are reproducible."""
    import warnings

    if path.exists():
        path.unlink()
    # Fixture 14 deliberately writes duplicate entry names; zipfile's writer
    # warning about that is the fixture's purpose, not a generation problem.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for name, body in entries:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, body, compresslevel=9)


def generate_pack_fixtures() -> None:
    """Generate fixtures 07-14 from the neutral demo-case-001 example (core-only)."""
    from oev.pack_verifier import (
        OVERALL_RECEIPT_VALID,
        PackSignatureState,
        build_pack_verification_receipt,
        verify_pack_offline,
        verify_pack_receipt,
    )
    from oev.replay import pin_pack, replay_snapshot
    from oev.trust import TrustStore

    # -------------------------------------------------------------
    # FIXTURE 07: 07-pack-replay-ok — pinned valid pack replays
    # -------------------------------------------------------------
    f7 = FIXTURES_DIR / "07-pack-replay-ok"
    f7.mkdir(exist_ok=True)
    _copy_example_pack(f7 / "pack")
    pin = pin_pack(f7 / "pack")
    (f7 / "pin.json").write_bytes(canonicalize_json(pin))
    replay = replay_snapshot(f7 / "pack", expected_pack_digest=pin["pack_digest"])
    assert replay.replay_status == "REPLAY_OK", replay.replay_status
    _write_expected(
        f7,
        {
            "replay_status": "REPLAY_OK",
            "eligible_fact_ids": list(replay.eligible_fact_ids),
            "note": "A valid pack replayed with the matching out-of-band pin succeeds; "
            "only snapshot-bound facts observed at or before captured_at are eligible.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 08: 08-pack-replay-hash-changed — pin refuses rewrite
    # -------------------------------------------------------------
    f8 = FIXTURES_DIR / "08-pack-replay-hash-changed"
    f8.mkdir(exist_ok=True)
    _copy_example_pack(f8 / "pack")
    original_pin = pin_pack(f8 / "pack")
    (f8 / "pin.json").write_bytes(canonicalize_json(original_pin))

    def _tamper_facts(doc: dict[str, Any]) -> dict[str, Any]:
        doc["facts"][0]["value"] = "99.9"  # rewrite a recorded reading
        return doc

    _rewrite_members_and_manifest(f8 / "pack", {"facts.json": _tamper_facts})
    replay = replay_snapshot(f8 / "pack", expected_pack_digest=original_pin["pack_digest"])
    assert replay.replay_status == "PACK_HASH_CHANGED", replay.replay_status
    _write_expected(
        f8,
        {
            "replay_status": "PACK_HASH_CHANGED",
            "pinned_pack_digest": original_pin["pack_digest"],
            "note": "The copy is internally self-consistent (digests and pack_digest agree), "
            "but the out-of-band pin anchors the original bytes: replay refuses.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 09: 09-pack-replay-snapshot-leak — late evidence refused
    # -------------------------------------------------------------
    f9 = FIXTURES_DIR / "09-pack-replay-snapshot-leak"
    f9.mkdir(exist_ok=True)
    _copy_example_pack(f9 / "pack")
    late_run = _late_reading_run()

    def _inject_late_fact(doc: dict[str, Any]) -> dict[str, Any]:
        doc["facts"].append(_late_reading_fact())
        return doc

    def _inject_late_run(doc: dict[str, Any]) -> dict[str, Any]:
        doc["rule_runs"].append(late_run)
        return doc

    _rewrite_members_and_manifest(
        f9 / "pack",
        {"facts.json": _inject_late_fact, "rule_runs.json": _inject_late_run},
    )
    replay = replay_snapshot(f9 / "pack")
    assert replay.replay_status == "SNAPSHOT_LEAK", replay.replay_status
    assert "fact-901" not in replay.eligible_fact_ids
    _write_expected(
        f9,
        {
            "replay_status": "SNAPSHOT_LEAK",
            "excluded_fact_id": "fact-901",
            "note": "A recorded rule run consumed a fact observed after the snapshot capture "
            "(2026-10-01T09:00:00Z > captured_at 2026-10-01T08:00:00Z): the recorded "
            "history contradicts the snapshot boundary, so the entire replay refuses.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 10: 10-pack-receipt-roundtrip — third-party offline receipt
    # -------------------------------------------------------------
    f10 = FIXTURES_DIR / "10-pack-receipt-roundtrip"
    f10.mkdir(exist_ok=True)
    _copy_example_pack(f10 / "pack")
    shutil.copy(EXAMPLE_KEYS, f10 / "verifier-keys.json")
    outcome = verify_pack_offline(f10 / "pack", trust_store=TrustStore.from_file(EXAMPLE_KEYS))
    assert outcome.overall == "PACK_VALID"
    receipt = build_pack_verification_receipt(
        outcome, receipt_id=FIXED_RECEIPT_ID, verified_at=FIXED_VERIFIED_AT
    )
    (f10 / "pack-verification-receipt.json").write_bytes(canonicalize_json(receipt))
    third_party = verify_pack_receipt(f10 / "pack-verification-receipt.json")
    assert third_party.overall == OVERALL_RECEIPT_VALID
    bound = verify_pack_receipt(f10 / "pack-verification-receipt.json", pack_dir=f10 / "pack")
    assert bound.pack_binding == "PACK_BINDING_MATCH"
    _write_expected(
        f10,
        {
            "receipt_overall": "RECEIPT_VALID",
            "is_dsse": False,
            "receipt_digest_valid": True,
            "recorded_pack_overall": "PACK_VALID",
            "recorded_signature_state": PackSignatureState.SIGNATURE_VALID.value,
            "pack_binding": "PACK_BINDING_MATCH",
            "receipt_id": FIXED_RECEIPT_ID,
            "verified_at": FIXED_VERIFIED_AT,
            "note": "A third party verifies the receipt offline from the receipt bytes alone; "
            "with the pack on disk, the recorded pack digest binds to the manifest "
            "actually present. The receipt records technical integrity only.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 11: 11-pack-signature-not-present — unsigned is not invalid
    # -------------------------------------------------------------
    f11 = FIXTURES_DIR / "11-pack-signature-not-present"
    f11.mkdir(exist_ok=True)
    _copy_example_pack(f11 / "pack")
    (f11 / "pack" / "manifest.dsse.json").unlink()
    outcome = verify_pack_offline(f11 / "pack")
    assert outcome.overall == "PACK_VALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_NOT_PRESENT.value
    _write_expected(
        f11,
        {
            "overall": "PACK_VALID",
            "signature_state": PackSignatureState.SIGNATURE_NOT_PRESENT.value,
            "manifest_signature_check": "NOT_APPLICABLE",
            "note": "An unsigned pack is never invalid because of the missing signature; "
            "its integrity stands on the manifest and member digests alone.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 12: 12-pack-signature-invalid — corrupt signature is invalid
    # -------------------------------------------------------------
    f12 = FIXTURES_DIR / "12-pack-signature-invalid"
    f12.mkdir(exist_ok=True)
    _copy_example_pack(f12 / "pack")
    shutil.copy(EXAMPLE_KEYS, f12 / "verifier-keys.json")
    envelope_path = f12 / "pack" / "manifest.dsse.json"
    envelope: dict[str, Any] = json.loads(envelope_path.read_bytes())
    raw_sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    raw_sig[0] ^= 0x01  # corrupt the signature bytes; payload and manifest stay intact
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(raw_sig)).decode("ascii")
    envelope_path.write_bytes(canonicalize_json(envelope))
    outcome = verify_pack_offline(f12 / "pack", trust_store=TrustStore.from_file(EXAMPLE_KEYS))
    assert outcome.overall == "PACK_VALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_INVALID.value
    assert outcome.signature_crypto_valid is False
    _write_expected(
        f12,
        {
            "overall": "PACK_VALID",
            "signature_state": PackSignatureState.SIGNATURE_INVALID.value,
            "signature_crypto_valid": False,
            "manifest_signature_check": "FAIL",
            "note": "A present-but-corrupt signature is SIGNATURE_INVALID — never valid, and "
            "never confused with an unsigned pack (fixture 11). Member integrity is "
            "unaffected, so the pack verdict stays PACK_VALID while the trust "
            "decision is reported honestly.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 13: 13-archive-traversal-refused — zip-slip rejected
    # -------------------------------------------------------------
    f13 = FIXTURES_DIR / "13-archive-traversal-refused"
    f13.mkdir(exist_ok=True)
    _deterministic_zip(
        f13 / "hostile.zip",
        [
            ("case.json", b'{"harmless": "entry"}'),
            ("../escaped.txt", b"this entry must never be extracted"),
        ],
    )
    _write_expected(
        f13,
        {
            "extraction_refused": True,
            "expected_error_contains": "traverses outside the root",
            "target_directory_untouched": True,
            "note": "Validate-before-extract: the traversal entry is rejected during "
            "inspection, so no file is ever written to the extraction root.",
        },
    )

    # -------------------------------------------------------------
    # FIXTURE 14: 14-archive-duplicate-member-refused — shadowing rejected
    # -------------------------------------------------------------
    f14 = FIXTURES_DIR / "14-archive-duplicate-member-refused"
    f14.mkdir(exist_ok=True)
    _deterministic_zip(
        f14 / "hostile.zip",
        [
            ("case.json", b'{"version": "first"}'),
            ("case.json", b'{"version": "second"}'),
        ],
    )
    _write_expected(
        f14,
        {
            "extraction_refused": True,
            "expected_error_contains": "duplicate entry name",
            "target_directory_untouched": True,
            "note": "Two entries claiming the same name are either corruption or an attempt "
            "to shadow a member with different content; both are refused.",
        },
    )

    print("All 8 decision pack conformance fixtures generated successfully.")


if __name__ == "__main__":
    if OEPT_DIR.is_dir():
        main()
    else:
        print(
            f"OEPT fixture corpus not found at {OEPT_DIR}; skipping fixtures 01-06 "
            "(they require the OEPT conformance corpus via OEPT_FIXTURES_DIR)."
        )
    generate_pack_fixtures()

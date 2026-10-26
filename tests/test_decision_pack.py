# SPDX-License-Identifier: Apache-2.0

"""Tests for the Decision Evidence Pack core (oev-decision-pack/0.2)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from oev.canonical import canonicalize_json
from oev.decision_models import DECISION_PACK_PROTOCOL_VERSION
from oev.decision_pack import (
    DecisionPackError,
    build_pack,
    compute_rule_digest,
    sign_pack_manifest,
    verify_pack,
)
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
EXAMPLE_PACK_DIR = EXAMPLES_DIR / "demo-case-001"
EXAMPLE_KEYS = EXAMPLES_DIR / "demo-case-001.verifier-keys.json"


def _rule(rule_id: str, version: str = "1.0.0") -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "rule_version": version,
        "description": f"Synthetic rule {rule_id}.",
        "condition": {"op": "eq", "args": [{"fact": "flag.enabled"}, {"const": True}]},
    }


def _write_source_dir(src: Path) -> str:
    """Write a minimal synthetic source directory; returns its case_id."""
    (src / "artifacts").mkdir(parents=True)
    (src / "artifacts" / "notes.txt").write_text("synthetic artifact bytes\n", encoding="utf-8")

    case = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "case_type": "synthetic-review",
        "opened_at": "2026-01-01T00:00:00Z",
    }
    facts = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "facts": [
            {
                "fact_id": "fact-001",
                "key": "flag.enabled",
                "value": True,
                "source": "synthetic-source",
                "observed_at": "2026-01-01T00:00:00Z",
            }
        ],
    }
    rule = _rule("flag-check")
    rule_runs = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "rule_runs": [
            {
                "run_id": "run-001",
                "rule": {**rule, "rule_digest": compute_rule_digest(rule)},
                "inputs": ["fact-001"],
                "outcome": "TRIGGERED",
                "executed_at": "2026-01-01T00:01:00Z",
                "executed_by": "synthetic-rules/0.1",
            }
        ],
    }
    findings = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "findings": [
            {
                "finding_id": "finding-001",
                "rule_run_id": "run-001",
                "severity": "LOW",
                "summary": "Synthetic finding from run-001.",
                "created_at": "2026-01-01T00:01:00Z",
            }
        ],
    }
    review_actions = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "review_actions": [
            {
                "action_id": "review-001",
                "action_type": "APPROVE",
                "actor": {"actor_id": "reviewer-001", "actor_type": "human"},
                "performed_at": "2026-01-01T00:02:00Z",
                "references_finding_ids": ["finding-001"],
                "note": "Synthetic approval.",
            }
        ],
    }
    timeline = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "events": [
            {
                "event_id": "evt-001",
                "sequence": 1,
                "event_type": "case.opened",
                "occurred_at": "2026-01-01T00:00:00Z",
                "summary": "Synthetic case opened.",
            }
        ],
    }
    snapshot_context = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "test-case-001",
        "snapshot_id": "snapshot-001",
        "captured_at": "2026-01-01T00:00:00Z",
        "sources": [
            {
                "source_id": "source-001",
                "kind": "synthetic",
                "digest": "sha256:" + hashlib.sha256(b"synthetic").hexdigest(),
            }
        ],
        "parameters": {"threshold": 1},
    }

    docs = {
        "case.json": case,
        "facts.json": facts,
        "rule_runs.json": rule_runs,
        "findings.json": findings,
        "review_actions.json": review_actions,
        "timeline.json": timeline,
        "snapshot_context.json": snapshot_context,
    }
    for name, doc in docs.items():
        (src / name).write_bytes(canonicalize_json(doc))
    return str(case["case_id"])


def _build_tmp_pack(tmp_path: Path, name: str = "pack") -> Path:
    src = tmp_path / f"{name}-src"
    out = tmp_path / name
    src.mkdir()
    _write_source_dir(src)
    build_pack(
        src_dir=src,
        out_dir=out,
        pack_id=f"pack-{name}",
        created_at="2026-01-01T00:10:00Z",
        creator_software="oev-test",
        creator_version="0.0.0",
    )
    return out


def test_example_pack_validates_and_signature_is_trusted() -> None:
    result = verify_pack(EXAMPLE_PACK_DIR, trust_store=TrustStore.from_file(EXAMPLE_KEYS))
    assert result.overall == "PACK_VALID"
    assert result.pack_digest_valid is True
    assert result.member_order_stable is True
    assert all(m.status == "MATCH" for m in result.member_results)
    assert len(result.member_results) == 9
    assert result.is_signed is True
    assert result.signature_crypto_valid is True
    assert result.is_trusted_signer is True
    assert result.trusted_signer_key_id == "demo-signer-2026-10"
    assert result.extra_files == []
    assert result.structure_errors == []


def test_example_pack_without_keys_is_valid_but_untrusted() -> None:
    result = verify_pack(EXAMPLE_PACK_DIR, trust_store=None)
    assert result.overall == "PACK_VALID"
    assert result.is_signed is True
    # The envelope embeds the signer's public key as an unauthenticated hint,
    # so the signature math verifies without any trust roots — trust stays NO.
    assert result.signature_crypto_valid is True
    assert result.is_trusted_signer is False


def test_pack_build_is_deterministic(tmp_path: Path) -> None:
    pack_a = _build_tmp_pack(tmp_path, "pack-a")
    pack_b = _build_tmp_pack(tmp_path, "pack-b")
    # pack_digest covers pack_id, so the two builds (which differ only in pack_id)
    # are compared member-by-member; the full-byte determinism check uses the
    # identical-ID builds below.
    for rel in [
        "case.json",
        "facts.json",
        "rule_runs.json",
        "findings.json",
        "review_actions.json",
        "timeline.json",
        "snapshot_context.json",
        "artifacts/notes.txt",
    ]:
        assert (pack_a / rel).read_bytes() == (pack_b / rel).read_bytes(), rel

    src = tmp_path / "det-src"
    src.mkdir()
    _write_source_dir(src)
    manifests = []
    for name in ["det-a", "det-b"]:
        out = tmp_path / name
        build_pack(
            src_dir=src,
            out_dir=out,
            pack_id="pack-det",
            created_at="2026-01-01T00:10:00Z",
            creator_software="oev-test",
            creator_version="0.0.0",
        )
        manifests.append((out / "manifest.json").read_bytes())
    assert manifests[0] == manifests[1]


def test_manifest_covers_every_member_in_stable_order(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    manifest = json.loads((pack_dir / "manifest.json").read_bytes())

    paths = [m["path"] for m in manifest["members"]]
    assert paths == sorted(paths)
    assert set(paths) == {
        "artifacts/notes.txt",
        "case.json",
        "facts.json",
        "rule_runs.json",
        "findings.json",
        "review_actions.json",
        "snapshot_context.json",
        "timeline.json",
    }

    for member in manifest["members"]:
        raw = (pack_dir / member["path"]).read_bytes()
        assert member["size_bytes"] == len(raw)
        assert member["sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
        if member["path"].endswith(".json"):
            assert member["canonicalization"] == "jcs-rfc8785"
            assert canonicalize_json(json.loads(raw)) == raw  # canonical storage, no trailing LF
        else:
            assert member["canonicalization"] == "raw"

    body = dict(manifest)
    declared = body.pop("pack_digest")
    assert declared == "sha256:" + hashlib.sha256(canonicalize_json(body)).hexdigest()


def test_tampered_member_is_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    findings_path = pack_dir / "findings.json"
    doc = json.loads(findings_path.read_bytes())
    doc["findings"][0]["severity"] = "CRITICAL"
    findings_path.write_bytes(canonicalize_json(doc))

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    tampered = [m for m in result.member_results if m.path == "findings.json"]
    assert tampered[0].status == "DIGEST_MISMATCH"


def test_non_canonical_member_is_rejected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    findings_path = pack_dir / "findings.json"
    doc = json.loads(findings_path.read_bytes())
    findings_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    flagged = [m for m in result.member_results if m.path == "findings.json"]
    assert flagged[0].status == "NOT_CANONICAL"


def test_missing_member_is_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    (pack_dir / "timeline.json").unlink()
    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert any(m.status == "MISSING" for m in result.member_results)


def test_unlisted_extra_file_is_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    (pack_dir / "stowaway.txt").write_text("hidden payload", encoding="utf-8")
    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert "stowaway.txt" in result.extra_files


def test_manifest_digest_tamper_is_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    manifest_path = pack_dir / "manifest.json"
    doc = json.loads(manifest_path.read_bytes())
    doc["pack_id"] = "pack-attacker-rewrote-this"
    manifest_path.write_bytes(canonicalize_json(doc))

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert result.pack_digest_valid is False


def test_rule_run_outcome_vocabulary_is_enforced(tmp_path: Path) -> None:
    src = tmp_path / "bad-src"
    out = tmp_path / "bad-pack"
    src.mkdir()
    _write_source_dir(src)
    rule_runs_path = src / "rule_runs.json"
    doc = json.loads(rule_runs_path.read_bytes())
    doc["rule_runs"][0]["outcome"] = "PASSED"
    rule_runs_path.write_bytes(canonicalize_json(doc))

    with pytest.raises(ValueError):
        build_pack(src_dir=src, out_dir=out, pack_id="pack-bad", created_at="2026-01-01T00:00:00Z")


def test_hash_mismatch_outcome_is_accepted(tmp_path: Path) -> None:
    src = tmp_path / "hm-src"
    out = tmp_path / "hm-pack"
    src.mkdir()
    _write_source_dir(src)
    rule_runs_path = src / "rule_runs.json"
    doc = json.loads(rule_runs_path.read_bytes())
    doc["rule_runs"][0]["outcome"] = "HASH_MISMATCH"
    doc["rule_runs"][0]["detail"] = "Input digest did not match recorded content; fail-closed."
    rule_runs_path.write_bytes(canonicalize_json(doc))

    build_pack(src_dir=src, out_dir=out, pack_id="pack-hm", created_at="2026-01-01T00:00:00Z")
    result = verify_pack(out)
    assert result.overall == "PACK_VALID"


def test_cross_reference_errors_are_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    findings_path = pack_dir / "findings.json"
    doc = json.loads(findings_path.read_bytes())
    doc["findings"][0]["rule_run_id"] = "run-does-not-exist"
    findings_path.write_bytes(canonicalize_json(doc))

    # The member digest no longer matches, so re-point the manifest at the new bytes
    # to isolate the cross-reference check from the digest check.
    manifest_path = pack_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for member in manifest["members"]:
        if member["path"] == "findings.json":
            member["size_bytes"] = findings_path.stat().st_size
            member["sha256"] = "sha256:" + hashlib.sha256(findings_path.read_bytes()).hexdigest()
    body = dict(manifest)
    body.pop("pack_digest")
    manifest["pack_digest"] = "sha256:" + hashlib.sha256(canonicalize_json(body)).hexdigest()
    manifest_path.write_bytes(canonicalize_json(manifest))

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert any("unknown rule_run_id" in e for e in result.structure_errors)


def test_dsse_sign_verify_and_tamper(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem, key_id="test-key-1")

    good_keys = tmp_path / "good-keys.json"
    good_keys.write_bytes(
        canonicalize_json([{"key_id": "test-key-1", "public_key_pem": public_pem.decode()}])
    )
    result = verify_pack(pack_dir, trust_store=TrustStore.from_file(good_keys))
    assert result.overall == "PACK_VALID"
    assert result.is_signed and result.is_trusted_signer and result.signature_crypto_valid

    # A wrong trust root must not trust the signer, but pack integrity is unchanged.
    other_private, other_public = generate_ed25519_keypair()
    wrong_keys = tmp_path / "wrong-keys.json"
    wrong_keys.write_bytes(
        canonicalize_json([{"key_id": "other", "public_key_pem": other_public.decode()}])
    )
    result = verify_pack(pack_dir, trust_store=TrustStore.from_file(wrong_keys))
    assert result.overall == "PACK_VALID"
    assert result.is_signed and not result.is_trusted_signer

    # Tampering with the envelope must break the signature binding to the manifest.
    envelope_path = pack_dir / "manifest.dsse.json"
    envelope = json.loads(envelope_path.read_bytes())
    envelope["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
    envelope_path.write_bytes(canonicalize_json(envelope))
    result = verify_pack(pack_dir, trust_store=TrustStore.from_file(good_keys))
    assert result.is_signed is True
    assert result.signature_crypto_valid is False
    assert result.is_trusted_signer is False

    # Signing must refuse a non-canonical manifest.
    manifest_path = pack_dir / "manifest.json"
    manifest_path.write_text(json.dumps(json.loads(manifest_path.read_bytes())), encoding="utf-8")
    with pytest.raises(DecisionPackError):
        sign_pack_manifest(pack_dir, other_private, key_id="k")


def test_dsse_envelope_payload_binds_exact_manifest_bytes(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, _public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem, key_id="bind-key")

    envelope = json.loads((pack_dir / "manifest.dsse.json").read_bytes())
    payload = base64.b64decode(envelope["payload"])
    assert payload == (pack_dir / "manifest.json").read_bytes()
    assert envelope["payloadType"] == "application/vnd.oev.decision-pack-manifest+json"


def test_case_id_mismatch_across_members_rejected(tmp_path: Path) -> None:
    src = tmp_path / "mismatch-src"
    out = tmp_path / "mismatch-pack"
    src.mkdir()
    _write_source_dir(src)
    facts_path = src / "facts.json"
    doc = json.loads(facts_path.read_bytes())
    doc["case_id"] = "other-case"
    facts_path.write_bytes(canonicalize_json(doc))

    with pytest.raises(DecisionPackError):
        build_pack(src_dir=src, out_dir=out, pack_id="pack-m", created_at="2026-01-01T00:00:00Z")


def test_example_contains_no_domain_leakage() -> None:
    """Guard: the example must stay domain-neutral (no finance-domain content)."""
    forbidden = [
        "invoice",
        "receivable",
        "credit",
        "loan",
        "payment",
        "customer",
        "fraud",
        "trade",
        "bank",
        "compliance",
        "kyc",
        "aml",
    ]
    texts: list[str] = []
    for path in sorted(EXAMPLE_PACK_DIR.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            try:
                texts.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                texts.append(raw.decode("latin-1"))
    combined = "\n".join(texts).lower()
    for word in forbidden:
        assert word not in combined, f"example must not contain '{word}'"


def test_neutral_example_member_files_are_canonical() -> None:
    for name in [
        "case.json",
        "facts.json",
        "rule_runs.json",
        "findings.json",
        "review_actions.json",
        "timeline.json",
        "snapshot_context.json",
        "manifest.json",
    ]:
        raw = (EXAMPLE_PACK_DIR / name).read_bytes()
        assert canonicalize_json(json.loads(raw)) == raw, name
        assert not raw.endswith(b"\n"), f"{name} must not end with a newline"

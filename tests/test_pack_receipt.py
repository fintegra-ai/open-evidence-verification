# SPDX-License-Identifier: Apache-2.0

"""Tests for the portable pack verification receipt (oev-pack-receipt/0.1) and the
honest three-way signature vocabulary of the offline pack verifier.

Covers, at the exact state-token level:

1. Three-way signature states — unsigned packs are never invalid
   (SIGNATURE_NOT_PRESENT), valid signatures are SIGNATURE_VALID (trusted or
   embedded-key-verified), and envelopes that are present but not established
   valid are SIGNATURE_INVALID — without ever being confused with "unsigned".
2. Receipt content — exactly which checks passed, failed, or were not run, plus
   the pack digest, the verifier identity/version, and the verification time.
3. Receipt round-trip — end to end over the neutral demo-case-001 example,
   unsigned and DSSE-signed, verified offline by a third party with and without
   the pack on disk, plus tamper and wrong-pack binding rejection.

Neutral fixtures only: the committed demo-case-001 example and synthetic packs.
No finance workflows, no customer data.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from oev import __version__
from oev.canonical import canonicalize_json
from oev.cli import main as cli_main
from oev.decision_models import MANIFEST_PAYLOAD_TYPE
from oev.decision_pack import sign_pack_manifest
from oev.dsse import compute_pae
from oev.hashing import sha256_bytes
from oev.pack_verifier import (
    CHECK_FAIL,
    CHECK_NOT_APPLICABLE,
    CHECK_NOT_RUN,
    CHECK_PASS,
    CHECK_UNVERIFIED,
    OVERALL_RECEIPT_INVALID,
    OVERALL_RECEIPT_VALID,
    PACK_BINDING_MATCH,
    PACK_BINDING_MISMATCH,
    PACK_BINDING_NOT_RUN,
    PACK_RECEIPT_PAYLOAD_TYPE,
    PACK_RECEIPT_PROTOCOL_VERSION,
    PACK_RECEIPT_SCHEMA_NAME,
    PackSignatureState,
    build_pack_verification_receipt,
    sign_pack_receipt,
    verify_pack_offline,
    verify_pack_receipt,
)
from oev.schemas import validate_document
from oev.signing import generate_ed25519_keypair, load_ed25519_private_key
from oev.trust import TrustStore
from tests.test_decision_pack import EXAMPLE_KEYS, EXAMPLE_PACK_DIR, _build_tmp_pack

PACK_CHECK_IDS_IN_ORDER = [
    "pack_present",
    "manifest_schema",
    "manifest_canonical",
    "pack_digest",
    "member_coverage",
    "snapshot_membership",
    "member_hashes",
    "cross_references",
    "manifest_signature",
]


def _trust_file(tmp_path: Path, key_id: str, public_pem: bytes) -> Path:
    keys_path = tmp_path / f"{key_id}-keys.json"
    keys_path.write_bytes(
        canonicalize_json([{"key_id": key_id, "public_key_pem": public_pem.decode("utf-8")}])
    )
    return keys_path


# ---------------------------------------------------------------------------
# 1. Honest three-way signature vocabulary (exact state tokens)
# ---------------------------------------------------------------------------


def test_unsigned_pack_is_not_present_and_never_invalid(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    outcome = verify_pack_offline(pack_dir)
    assert outcome.overall == "PACK_VALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_NOT_PRESENT.value
    assert outcome.signature_crypto_valid is False
    assert outcome.is_trusted_signer is False
    # An unsigned pack is never failed because of the missing signature.
    assert outcome.check_status("manifest_signature") == CHECK_NOT_APPLICABLE
    assert outcome.check_status("member_hashes") == CHECK_PASS


def test_valid_signature_is_valid_and_trusted_with_pinned_roots() -> None:
    outcome = verify_pack_offline(EXAMPLE_PACK_DIR, trust_store=TrustStore.from_file(EXAMPLE_KEYS))
    assert outcome.overall == "PACK_VALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_VALID.value
    assert outcome.signature_crypto_valid is True
    assert outcome.is_trusted_signer is True
    assert outcome.check_status("manifest_signature") == CHECK_PASS


def test_valid_signature_from_untrusted_signer_is_valid_but_not_trusted(
    tmp_path: Path,
) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, _public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem, key_id="honest-signer")

    # An unrelated party's roots: the signature math still verifies via the
    # embedded public-key hint, so the state is VALID — trust stays NO.
    _priv, unrelated_pub = generate_ed25519_keypair()
    unrelated_keys = _trust_file(tmp_path, "other-party", unrelated_pub)

    outcome = verify_pack_offline(pack_dir, trust_store=TrustStore.from_file(unrelated_keys))
    assert outcome.overall == "PACK_VALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_VALID.value
    assert outcome.signature_crypto_valid is True
    assert outcome.is_trusted_signer is False
    assert outcome.check_status("manifest_signature") == CHECK_PASS

    # A caller who pinned unrelated roots sees the trust failure (exit 2),
    # never silence and never a downgrade of pack integrity.
    rc = cli_main(["pack", "verify", str(pack_dir), "--verifier-keys", str(unrelated_keys)])
    assert rc == 2


def test_signature_without_available_keys_is_invalid_but_pack_stays_valid(
    tmp_path: Path,
) -> None:
    # A signed pack whose envelope carries no embedded key hint, verified with
    # no caller trust roots: verification cannot even be attempted. The honest
    # state is INVALID (present but not established valid) with an UNVERIFIED
    # check — never "unsigned", and never a downgrade of member integrity.
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, _public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem, key_id="hintless-signer")
    envelope_path = pack_dir / "manifest.dsse.json"
    envelope = json.loads(envelope_path.read_bytes())
    for entry in envelope["signatures"]:
        entry.pop("public_key_pem", None)
    envelope_path.write_bytes(canonicalize_json(envelope))

    outcome = verify_pack_offline(pack_dir)
    assert outcome.overall == "PACK_VALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_INVALID.value
    assert outcome.signature_crypto_valid is False
    assert outcome.check_status("manifest_signature") == CHECK_UNVERIFIED


def test_stripped_signature_is_reported_not_present(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, _public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem)
    before = verify_pack_offline(pack_dir)
    assert before.signature_state == PackSignatureState.SIGNATURE_VALID.value

    (pack_dir / "manifest.dsse.json").unlink()
    after = verify_pack_offline(pack_dir)
    assert after.overall == "PACK_VALID"
    assert after.signature_state == PackSignatureState.SIGNATURE_NOT_PRESENT.value
    assert after.check_status("manifest_signature") == CHECK_NOT_APPLICABLE


def test_replaced_signature_is_detected_without_confusing_unsigned(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem, key_id="original-signer")
    original_keys = _trust_file(tmp_path, "original-signer", public_pem)
    trust = TrustStore.from_file(original_keys)

    # Flavor 1: attacker re-signs with their own key, embedding its public key.
    # The signature math verifies via the hint → VALID, but trust stays NO:
    # with the original roots pinned, the replacement is a visible failure
    # (exit 2), never silence.
    attacker_pem, _attacker_pub = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, attacker_pem, key_id="original-signer")
    replaced = verify_pack_offline(pack_dir, trust_store=trust)
    assert replaced.overall == "PACK_VALID"  # member integrity is untouched
    assert replaced.signature_state == PackSignatureState.SIGNATURE_VALID.value
    assert replaced.signature_crypto_valid is True
    assert replaced.is_trusted_signer is False
    assert cli_main(["pack", "verify", str(pack_dir), "--verifier-keys", str(original_keys)]) == 2

    # Flavor 2: attacker envelope without any usable key material (spoofed
    # keyid only). Verification is attempted against the pinned root and
    # fails → SIGNATURE_INVALID with a FAIL check — present-but-broken is
    # never reported as "unsigned".
    manifest_bytes = (pack_dir / "manifest.json").read_bytes()
    raw = {
        "payloadType": MANIFEST_PAYLOAD_TYPE,
        "payload": base64.b64encode(manifest_bytes).decode("ascii"),
        "signatures": [
            {"sig": base64.b64encode(b"\x00" * 64).decode("ascii"), "keyid": "original-signer"}
        ],
    }
    (pack_dir / "manifest.dsse.json").write_bytes(canonicalize_json(raw))
    broken = verify_pack_offline(pack_dir, trust_store=trust)
    assert broken.overall == "PACK_VALID"
    assert broken.signature_state == PackSignatureState.SIGNATURE_INVALID.value
    assert broken.signature_crypto_valid is False
    assert broken.is_trusted_signer is False
    assert broken.check_status("manifest_signature") == CHECK_FAIL


def test_envelope_over_foreign_manifest_invalidates_pack(tmp_path: Path) -> None:
    """A cryptographically valid signature over the wrong manifest bytes is a
    structural binding failure: the pack itself is invalid."""
    pack_dir = _build_tmp_pack(tmp_path)
    stored_manifest = (pack_dir / "manifest.json").read_bytes()
    foreign = json.loads(stored_manifest)
    foreign["pack_id"] = "pack-foreign-rewrite"
    foreign_bytes = canonicalize_json(foreign)
    assert foreign_bytes != stored_manifest

    attacker_pem, attacker_pub = generate_ed25519_keypair()
    attacker_key = load_ed25519_private_key(attacker_pem)
    envelope = {
        "payloadType": MANIFEST_PAYLOAD_TYPE,
        "payload": base64.b64encode(foreign_bytes).decode("ascii"),
        "signatures": [
            {
                "sig": base64.b64encode(
                    attacker_key.sign(compute_pae(MANIFEST_PAYLOAD_TYPE, foreign_bytes))
                ).decode("ascii"),
                "public_key_pem": attacker_pub.decode("utf-8"),
            }
        ],
    }
    (pack_dir / "manifest.dsse.json").write_bytes(canonicalize_json(envelope))

    outcome = verify_pack_offline(pack_dir)
    assert outcome.overall == "PACK_INVALID"
    assert outcome.signature_state == PackSignatureState.SIGNATURE_INVALID.value
    assert outcome.check_status("manifest_signature") == CHECK_FAIL


# ---------------------------------------------------------------------------
# 2. Receipt content: checks, pack hash, verifier identity, time
# ---------------------------------------------------------------------------


def test_receipt_records_full_check_vector_digest_and_verifier() -> None:
    outcome = verify_pack_offline(EXAMPLE_PACK_DIR, trust_store=TrustStore.from_file(EXAMPLE_KEYS))
    receipt = build_pack_verification_receipt(
        outcome,
        receipt_id="00000000-0000-4000-8000-000000000042",
        verified_at="2026-10-01T12:00:00Z",
    )
    manifest = json.loads((EXAMPLE_PACK_DIR / "manifest.json").read_bytes())
    assert receipt["protocol_version"] == PACK_RECEIPT_PROTOCOL_VERSION
    assert receipt["receipt_id"] == "00000000-0000-4000-8000-000000000042"
    assert receipt["pack_id"] == manifest["pack_id"]
    assert receipt["case_id"] == manifest["case_id"]
    assert receipt["pack_digest"] == manifest["pack_digest"]
    assert receipt["recomputed_pack_digest"] == manifest["pack_digest"]
    assert receipt["pack_digest_valid"] is True
    assert receipt["overall"] == "PACK_VALID"
    assert receipt["signature_state"] == PackSignatureState.SIGNATURE_VALID.value
    assert receipt["verified_at"] == "2026-10-01T12:00:00Z"
    assert receipt["verifier"] == {"software": "oev", "version": __version__}

    assert [c["check_id"] for c in receipt["checks"]] == PACK_CHECK_IDS_IN_ORDER
    assert all(c["status"] == CHECK_PASS for c in receipt["checks"])
    assert all(m["status"] == "MATCH" for m in receipt["member_results"])
    assert len(receipt["member_results"]) == len(manifest["members"])

    body = dict(receipt)
    body.pop("receipt_digest")
    assert receipt["receipt_digest"] == sha256_bytes(canonicalize_json(body))
    validate_document(receipt, PACK_RECEIPT_SCHEMA_NAME)


def test_receipt_records_failed_checks_for_tampered_pack(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    facts_path = pack_dir / "facts.json"
    facts = json.loads(facts_path.read_bytes())
    facts["facts"][0]["value"] = "999.9"
    facts_path.write_bytes(canonicalize_json(facts))

    outcome = verify_pack_offline(pack_dir)
    assert outcome.overall == "PACK_INVALID"
    receipt = build_pack_verification_receipt(outcome)

    by_id = {c["check_id"]: c for c in receipt["checks"]}
    assert by_id["member_hashes"]["status"] == CHECK_FAIL
    assert by_id["snapshot_membership"]["status"] == CHECK_PASS
    assert receipt["overall"] == "PACK_INVALID"
    assert any(m["status"] == "DIGEST_MISMATCH" for m in receipt["member_results"])

    # A receipt of a failed verification is itself an intact, portable record
    # of that failure — RECEIPT_VALID never implies PACK_VALID.
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(canonicalize_json(receipt))
    result = verify_pack_receipt(receipt_path)
    assert result.overall == OVERALL_RECEIPT_VALID
    assert result.receipt["overall"] == "PACK_INVALID"


def test_receipt_records_not_run_and_not_applicable_checks(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    (pack_dir / "manifest.json").unlink()

    outcome = verify_pack_offline(pack_dir)
    receipt = build_pack_verification_receipt(outcome)

    statuses = [(c["check_id"], c["status"]) for c in receipt["checks"]]
    assert statuses[0] == ("pack_present", CHECK_FAIL)
    assert statuses[-1] == ("manifest_signature", CHECK_NOT_APPLICABLE)
    assert all(status == CHECK_NOT_RUN for _, status in statuses[1:-1])
    assert receipt["pack_digest"] == ""
    assert receipt["recomputed_pack_digest"] == ""
    assert receipt["overall"] == "PACK_INVALID"
    validate_document(receipt, PACK_RECEIPT_SCHEMA_NAME)


# ---------------------------------------------------------------------------
# 3. Receipt round-trip: third-party offline verification
# ---------------------------------------------------------------------------


def test_unsigned_receipt_verifies_offline_as_third_party(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack_dir))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(canonicalize_json(receipt))

    result = verify_pack_receipt(receipt_path)
    assert result.overall == OVERALL_RECEIPT_VALID
    assert result.is_dsse is False
    assert result.schema_valid is True
    assert result.receipt_digest_valid is True
    assert result.signature_state == PackSignatureState.SIGNATURE_NOT_PRESENT.value
    assert result.pack_binding == PACK_BINDING_NOT_RUN

    # With the pack on disk, the receipt binds to exactly those pack bytes.
    bound = verify_pack_receipt(receipt_path, pack_dir=pack_dir)
    assert bound.pack_binding == PACK_BINDING_MATCH
    assert bound.overall == OVERALL_RECEIPT_VALID


def test_signed_receipt_third_party_verification_with_and_without_roots(
    tmp_path: Path,
) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack_dir))
    private_pem, public_pem = generate_ed25519_keypair()
    envelope = sign_pack_receipt(receipt, private_pem, key_id="receipt-signer")
    env_path = tmp_path / "receipt.dsse.json"
    env_path.write_bytes(canonicalize_json(envelope))

    # No trust roots anywhere: the signature math verifies via the embedded
    # public-key hint; trust is reported as NO and never implied.
    result = verify_pack_receipt(env_path)
    assert result.overall == OVERALL_RECEIPT_VALID
    assert result.is_dsse is True
    assert result.signature_state == PackSignatureState.SIGNATURE_VALID.value
    assert result.signature_crypto_valid is True
    assert result.is_trusted_signer is False

    # With the receipt signer pinned, the signer is trusted.
    signer_keys = _trust_file(tmp_path, "receipt-signer", public_pem)
    trusted = verify_pack_receipt(env_path, trust_store=TrustStore.from_file(signer_keys))
    assert trusted.is_trusted_signer is True
    assert trusted.trusted_signer_key_id == "receipt-signer"


def test_cli_receipt_round_trip_end_to_end_demo_case(tmp_path: Path) -> None:
    """End-to-end round trip over the neutral demo-case-001 example.

    Verify the pack, emit the receipt, then verify the receipt as a third
    party — with the pack present (binding) and with the receipt alone
    (pure offline portability).
    """
    receipt_path = tmp_path / "receipt.json"
    rc = cli_main(
        [
            "pack",
            "verify",
            str(EXAMPLE_PACK_DIR),
            "--verifier-keys",
            str(EXAMPLE_KEYS),
            "--out",
            str(receipt_path),
        ]
    )
    assert rc == 0
    stored = json.loads(receipt_path.read_bytes())
    assert stored["protocol_version"] == PACK_RECEIPT_PROTOCOL_VERSION
    assert stored["signature_state"] == PackSignatureState.SIGNATURE_VALID.value

    rc = cli_main(["pack", "receipt", "verify", str(receipt_path), "--pack", str(EXAMPLE_PACK_DIR)])
    assert rc == 0

    rc = cli_main(["pack", "receipt", "verify", str(receipt_path)])
    assert rc == 0


def test_cli_signed_receipt_round_trip_end_to_end_demo_case(tmp_path: Path) -> None:
    private_pem, public_pem = generate_ed25519_keypair()
    signer_key = tmp_path / "receipt-signer.pem"
    signer_key.write_bytes(private_pem)
    signer_keys = _trust_file(tmp_path, "receipt-signer", public_pem)
    env_path = tmp_path / "receipt.dsse.json"

    rc = cli_main(
        [
            "pack",
            "verify",
            str(EXAMPLE_PACK_DIR),
            "--verifier-keys",
            str(EXAMPLE_KEYS),
            "--out",
            str(env_path),
            "--sign-receipt",
            str(signer_key),
            "--signer-key-id",
            "receipt-signer",
        ]
    )
    assert rc == 0
    envelope = json.loads(env_path.read_bytes())
    assert envelope["payloadType"] == PACK_RECEIPT_PAYLOAD_TYPE

    # Third party, receipt only, signer pinned: offline verifiable.
    rc = cli_main(["pack", "receipt", "verify", str(env_path), "--verifier-keys", str(signer_keys)])
    assert rc == 0

    # Same receipt without any roots: still verifiable (embedded hint),
    # exit 0 because the signature itself is VALID.
    rc = cli_main(["pack", "receipt", "verify", str(env_path)])
    assert rc == 0


def test_tampered_receipt_fails_third_party_verification(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack_dir))

    tampered = dict(receipt)
    tampered["checks"] = [dict(c) for c in receipt["checks"]]
    tampered["checks"][6]["status"] = CHECK_FAIL  # member_hashes
    result = verify_pack_receipt(tampered)
    assert result.overall == OVERALL_RECEIPT_INVALID
    assert result.receipt_digest_valid is False


def test_receipt_presented_for_different_pack_is_rejected(tmp_path: Path) -> None:
    pack_a = _build_tmp_pack(tmp_path, "pack-a")
    pack_b = _build_tmp_pack(tmp_path, "pack-b")
    receipt = build_pack_verification_receipt(verify_pack_offline(pack_a))

    mismatch = verify_pack_receipt(receipt, pack_dir=pack_b)
    assert mismatch.pack_binding == PACK_BINDING_MISMATCH
    assert mismatch.overall == OVERALL_RECEIPT_INVALID

    match = verify_pack_receipt(receipt, pack_dir=pack_a)
    assert match.pack_binding == PACK_BINDING_MATCH
    assert match.overall == OVERALL_RECEIPT_VALID


def test_signed_receipt_tamper_is_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack_dir))
    private_pem, _public_pem = generate_ed25519_keypair()
    envelope = sign_pack_receipt(receipt, private_pem)
    env_path = tmp_path / "receipt.dsse.json"
    env_path.write_bytes(canonicalize_json(envelope))

    # a) Tampered payload: the receipt self-digest no longer matches → invalid.
    payload_env = json.loads(env_path.read_bytes())
    payload = bytearray(base64.b64decode(payload_env["payload"]))
    payload[0] ^= 0x01
    payload_env["payload"] = base64.b64encode(bytes(payload)).decode("ascii")
    tampered_payload = verify_pack_receipt(payload_env)
    assert tampered_payload.overall == OVERALL_RECEIPT_INVALID

    # b) Tampered signature: the receipt content is intact (RECEIPT_VALID) but
    # the signature state is honestly SIGNATURE_INVALID → CLI exit 2.
    sig_env = json.loads(env_path.read_bytes())
    sig = bytearray(base64.b64decode(sig_env["signatures"][0]["sig"]))
    sig[0] ^= 0x01
    sig_env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode("ascii")
    tampered_sig = verify_pack_receipt(sig_env)
    assert tampered_sig.overall == OVERALL_RECEIPT_VALID
    assert tampered_sig.signature_state == PackSignatureState.SIGNATURE_INVALID.value
    assert tampered_sig.signature_crypto_valid is False

    tampered_path = tmp_path / "receipt-tampered-sig.json"
    tampered_path.write_bytes(canonicalize_json(sig_env))
    assert cli_main(["pack", "receipt", "verify", str(tampered_path)]) == 2


def test_receipt_schema_rejects_unknown_signature_state(tmp_path: Path) -> None:
    """The receipt schema pins the three-way vocabulary: no other value fits."""
    pack_dir = _build_tmp_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack_dir))
    forged = dict(receipt)
    forged["signature_state"] = "SIGNATURE_MAYBE"
    try:
        validate_document(forged, PACK_RECEIPT_SCHEMA_NAME)
    except ValueError:
        pass
    else:
        raise AssertionError("schema accepted a forged signature_state")

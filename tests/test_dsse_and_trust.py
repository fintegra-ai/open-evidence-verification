# SPDX-License-Identifier: Apache-2.0

import base64

import pytest

from oev.dsse import (
    DEFAULT_PAYLOAD_TYPE,
    DsseError,
    compute_pae,
    parse_dsse_envelope,
)
from oev.models import (
    CheckResult,
    CheckStatus,
    OverallResult,
    PackageReference,
    ProfileReference,
    TrustInput,
    VerificationReceipt,
    VerifierIdentity,
)
from oev.receipts import finalize_receipt
from oev.signing import (
    generate_ed25519_keypair,
    sign_receipt_dsse,
    verify_dsse_signature_with_key,
)
from oev.trust import TrustedKey, TrustStore, evaluate_receipt_trust


def make_sample_receipt() -> VerificationReceipt:
    raw = VerificationReceipt(
        receipt_id="00000000-0000-4000-8000-000000000002",
        protocol_version="oev-receipt/0.1",
        recorded_verification_time="2026-01-01T12:00:00Z",
        package=PackageReference(digest="sha256:" + "1" * 64, format="oept-bundle/0.1"),
        profile=ProfileReference(
            profile_id="sample-prof",
            profile_version="0.1",
            profile_digest="sha256:" + "2" * 64,
        ),
        verifier=VerifierIdentity(software="oev-test", version="0.1.0"),
        trust_inputs=[TrustInput(trust_id="k1", type="public_key", digest="sha256:" + "3" * 64)],
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
        ],
        limitations=[],
        overall_result=OverallResult.TECHNICAL_CHECKS_PASSED,
    )
    return finalize_receipt(raw)


def test_dsse_pae_computation():
    pae = compute_pae("test-type", b"test-payload")
    # Expected: b"DSSEv1 9 test-type 12 test-payload"
    assert pae == b"DSSEv1 9 test-type 12 test-payload"


def test_dsse_signing_and_verification():
    priv_pem, pub_pem = generate_ed25519_keypair()
    receipt = make_sample_receipt()

    envelope = sign_receipt_dsse(receipt, priv_pem, key_id="signer-01")
    assert envelope["payloadType"] == DEFAULT_PAYLOAD_TYPE
    assert len(envelope["signatures"]) == 1
    assert envelope["signatures"][0]["keyid"] == "signer-01"

    # Verify signature
    assert verify_dsse_signature_with_key(envelope, pub_pem) is True

    # With wrong key
    _, other_pub = generate_ed25519_keypair()
    assert verify_dsse_signature_with_key(envelope, other_pub) is False


def test_tampered_dsse_payload():
    priv_pem, pub_pem = generate_ed25519_keypair()
    receipt = make_sample_receipt()
    envelope = sign_receipt_dsse(receipt, priv_pem, key_id="signer-01")

    # Tamper payload bytes (decode, alter 1 character, re-encode)
    payload_bytes = base64.b64decode(envelope["payload"])
    tampered_bytes = payload_bytes.replace(b"oev-test", b"bad-test")
    assert tampered_bytes != payload_bytes

    tampered_envelope = dict(envelope)
    tampered_envelope["payload"] = base64.b64encode(tampered_bytes).decode("ascii")

    # Signature verification MUST fail
    assert verify_dsse_signature_with_key(tampered_envelope, pub_pem) is False


def test_tampered_dsse_signature():
    priv_pem, pub_pem = generate_ed25519_keypair()
    receipt = make_sample_receipt()
    envelope = sign_receipt_dsse(receipt, priv_pem, key_id="signer-01")

    # Corrupt signature bytes
    sig_entry = envelope["signatures"][0]
    raw_sig = bytearray(base64.b64decode(sig_entry["sig"]))
    raw_sig[0] ^= 0xFF
    corrupted_sig = base64.b64encode(bytes(raw_sig)).decode("ascii")

    corrupted_envelope = {
        "payloadType": envelope["payloadType"],
        "payload": envelope["payload"],
        "signatures": [{"keyid": "signer-01", "sig": corrupted_sig}],
    }
    assert verify_dsse_signature_with_key(corrupted_envelope, pub_pem) is False


def test_attacker_self_key_hostile_test():
    """Attacker creates a receipt, generates own key, signs it, and claims a keyid.
    Without caller trust key, this must NEVER be trusted.
    """
    attacker_priv, attacker_pub = generate_ed25519_keypair()
    _legit_priv, legit_pub = generate_ed25519_keypair()

    receipt = make_sample_receipt()
    attacker_envelope = sign_receipt_dsse(receipt, attacker_priv, key_id="trusted-verifier-corp")

    # 1. Caller provides NO trust store -> untrusted
    eval_no_store = evaluate_receipt_trust(attacker_envelope, trust_store=None)
    assert eval_no_store.is_trusted is False
    assert eval_no_store.crypto_valid is False

    # 2. Caller provides trust store with ONLY legitimate verifier -> untrusted
    trust_store = TrustStore.from_list(
        [{"key_id": "legit-01", "public_key_pem": legit_pub.decode("utf-8")}]
    )
    eval_legit_store = evaluate_receipt_trust(attacker_envelope, trust_store=trust_store)
    assert eval_legit_store.is_trusted is False
    assert eval_legit_store.trusted_key_id is None

    # 3. If caller explicitly adds attacker key to their trust store -> trusted
    trust_store_with_attacker = TrustStore.from_list(
        [{"key_id": "audited-signer", "public_key_pem": attacker_pub.decode("utf-8")}]
    )
    eval_explicit = evaluate_receipt_trust(attacker_envelope, trust_store=trust_store_with_attacker)
    assert eval_explicit.is_trusted is True
    assert eval_explicit.trusted_key_id == "audited-signer"


def test_duplicate_trust_key_id_rejected():
    _, pub = generate_ed25519_keypair()
    store = TrustStore()
    k1 = TrustedKey.from_dict({"key_id": "k1", "public_key_pem": pub.decode("utf-8")})
    store.add_key(k1)
    with pytest.raises(ValueError, match="Duplicate trusted key ID"):
        store.add_key(k1)


def test_malformed_dsse_envelopes():
    with pytest.raises(DsseError, match="must be a JSON object"):
        parse_dsse_envelope("not a dict")  # type: ignore[arg-type]

    with pytest.raises(DsseError, match="payloadType"):
        parse_dsse_envelope({"payload": "abcd", "signatures": []})

    with pytest.raises(DsseError, match="invalid Base64"):
        parse_dsse_envelope(
            {"payloadType": "test", "payload": "not valid base64!@#", "signatures": [{"sig": "a"}]}
        )

    with pytest.raises(DsseError, match="must be a non-empty array"):
        parse_dsse_envelope({"payloadType": "test", "payload": "abcd", "signatures": []})

# SPDX-License-Identifier: Apache-2.0

"""Tests for signed revocation lists (HEA design §9.1)."""

from __future__ import annotations

import base64
import json

import pytest

from oev.canonical import canonicalize_json
from oev.revocation import (
    RevocationEntry,
    RevocationList,
    build_revocation_list,
    verify_revocation_list,
)
from oev.trust import TrustStore
from tests.hea_helpers import CLAIMED_TIME, make_keypair


def _authority() -> tuple[bytes, dict[str, object]]:
    priv, _pub, entry = make_keypair(role=None)
    entry["key_id"] = "rev-1"
    return priv, entry


def test_build_and_verify_roundtrip() -> None:
    priv, entry = _authority()
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="key-compromise", revoked_at_claimed=CLAIMED_TIME)],
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        private_key_pem=priv,
    )
    store = TrustStore.from_list([entry])
    revocation, note = verify_revocation_list(envelope, store)
    assert revocation is not None
    assert revocation.is_revoked("wit-1")
    assert not revocation.is_revoked("wit-2")
    assert revocation.revoked_key_ids() == {"wit-1"}
    assert "1 entries" in note


def test_empty_revocation_list_is_valid() -> None:
    priv, entry = _authority()
    envelope = build_revocation_list([], "rev-1", CLAIMED_TIME, priv)
    revocation, _note = verify_revocation_list(envelope, TrustStore.from_list([entry]))
    assert revocation is not None
    assert revocation.entries == []


def test_untrusted_authority_is_not_honoured() -> None:
    priv, _entry = _authority()
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="x", revoked_at_claimed=CLAIMED_TIME)],
        "rev-1",
        CLAIMED_TIME,
        priv,
    )
    _other_priv, _other_pub, other_entry = make_keypair(role=None)
    other_entry["key_id"] = "rev-2"
    revocation, note = verify_revocation_list(envelope, TrustStore.from_list([other_entry]))
    assert revocation is None
    assert "not trusted" in note


def test_no_authority_store_is_unknown_not_clean() -> None:
    priv, _entry = _authority()
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="x", revoked_at_claimed=CLAIMED_TIME)],
        "rev-1",
        CLAIMED_TIME,
        priv,
    )
    revocation, note = verify_revocation_list(envelope, None)
    assert revocation is None
    assert "unknown" in note


def test_tampered_entry_after_signing_fails() -> None:
    priv, entry = _authority()
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="x", revoked_at_claimed=CLAIMED_TIME)],
        "rev-1",
        CLAIMED_TIME,
        priv,
    )
    raw = bytearray(base64.b64decode(envelope["payload"].encode()))
    raw[-5] = ord("Z") if raw[-5] != ord("Z") else ord("Y")
    envelope["payload"] = base64.b64encode(bytes(raw)).decode()
    revocation, _note = verify_revocation_list(envelope, TrustStore.from_list([entry]))
    assert revocation is None


def test_wrong_payload_type_not_honoured() -> None:
    priv, entry = _authority()
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="x", revoked_at_claimed=CLAIMED_TIME)],
        "rev-1",
        CLAIMED_TIME,
        priv,
    )
    envelope["payloadType"] = "application/vnd.oev.execution-attestation+json"
    revocation, _note = verify_revocation_list(envelope, TrustStore.from_list([entry]))
    assert revocation is None


def test_duplicate_key_id_entries_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate key_id"):
        RevocationList.from_dict(
            {
                "protocol_version": "oev-revocation/0.1",
                "issuer_key_id": "rev-1",
                "issued_at_claimed": CLAIMED_TIME,
                "entries": [
                    {"key_id": "wit-1", "reason": "a", "revoked_at_claimed": CLAIMED_TIME},
                    {"key_id": "wit-1", "reason": "b", "revoked_at_claimed": CLAIMED_TIME},
                ],
            }
        )


def test_entry_limit_enforced() -> None:
    entries = [
        {"key_id": f"k-{i}", "reason": "x", "revoked_at_claimed": CLAIMED_TIME} for i in range(1025)
    ]
    with pytest.raises(ValueError, match="exceeds"):
        RevocationList.from_dict(
            {
                "protocol_version": "oev-revocation/0.1",
                "issuer_key_id": "rev-1",
                "issued_at_claimed": CLAIMED_TIME,
                "entries": entries,
            }
        )


def test_unsupported_protocol_version_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported revocation protocol version"):
        RevocationList.from_dict(
            {
                "protocol_version": "oev-revocation/9.9",
                "issuer_key_id": "rev-1",
                "issued_at_claimed": CLAIMED_TIME,
                "entries": [],
            }
        )


def test_revocation_list_schema_validated() -> None:
    from oev.schemas import validate_document

    priv, _entry = _authority()
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="x", revoked_at_claimed=CLAIMED_TIME)],
        "rev-1",
        CLAIMED_TIME,
        priv,
    )
    payload = json.loads(base64.b64decode(envelope["payload"].encode()))
    validate_document(payload, "revocation-list-0.1.schema.json")
    assert canonicalize_json(payload)


def test_malformed_envelope_is_unknown() -> None:
    revocation, note = verify_revocation_list({"payloadType": "x"}, TrustStore.from_list([]))
    assert revocation is None
    assert note

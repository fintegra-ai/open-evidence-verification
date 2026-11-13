# SPDX-License-Identifier: Apache-2.0

"""Round-3 (P0) witness-authorisation document tests (HEA §9.2).

The authorisation record is schema-bound (oev-witness-authorization/0.1):
witness key, issuer, authorised profiles/checks, validity window,
revocation. Missing or mismatched authorisation fails closed as
UNPROVEN / WITNESS_UNAUTHORIZED — never silently, never as a crash.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oev.hea_verifier import verify_historical_execution
from oev.witness_authorization import (
    check_witness_authorization,
    load_witness_authorization_document,
)
from tests.hea_helpers import CLAIMED_TIME, build_valid_hea, hea_inputs


def make_auth(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "protocol_version": "oev-witness-authorization/0.1",
        "witness_key_id": "wit-1",
        "issuer_key_id": "operator-1",
        "authorized_profiles": ["strict-conformance-profile"],
        "valid_from_claimed": "2026-01-01T00:00:00Z",
        "valid_until_claimed": "2027-12-31T23:59:59Z",
    }
    doc.update(overrides)
    return doc


def test_valid_document_passes(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, witness_authorization_document=make_auth())
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_document_for_other_profile_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(
            bundle,
            witness_authorization_document=make_auth(authorized_profiles=["other-profile"]),
        )
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "WITNESS_UNAUTHORIZED"


def test_empty_authorized_profiles_authorises_nothing(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, witness_authorization_document=make_auth(authorized_profiles=[]))
    )
    assert result.reason == "WITNESS_UNAUTHORIZED"


def test_document_for_other_key_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, witness_authorization_document=make_auth(witness_key_id="wit-9"))
    )
    assert result.reason == "WITNESS_UNAUTHORIZED"


def test_revoked_document_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(
            bundle,
            witness_authorization_document=make_auth(
                revoked=True, revocation_reason="key-compromise"
            ),
        )
    )
    assert result.reason == "WITNESS_UNAUTHORIZED"
    assert any("revoked" in note.lower() for note in result.notes)


def test_check_restriction_enforced(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    ok = verify_historical_execution(
        hea_inputs(
            bundle,
            witness_authorization_document=make_auth(
                authorized_checks=["archive_safety", "manifest_structure"]
            ),
        )
    )
    assert ok.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    missing = verify_historical_execution(
        hea_inputs(
            bundle,
            witness_authorization_document=make_auth(authorized_checks=["archive_safety"]),
        )
    )
    assert missing.reason == "WITNESS_UNAUTHORIZED"
    empty = verify_historical_execution(
        hea_inputs(bundle, witness_authorization_document=make_auth(authorized_checks=[]))
    )
    assert empty.reason == "WITNESS_UNAUTHORIZED"


def test_validity_window_enforced(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    expired = verify_historical_execution(
        hea_inputs(
            bundle,
            witness_authorization_document=make_auth(
                valid_until_claimed="2026-11-01T00:00:00Z"  # before CLAIMED_TIME
            ),
        )
    )
    assert expired.reason == "WITNESS_UNAUTHORIZED"
    not_yet = verify_historical_execution(
        hea_inputs(
            bundle,
            witness_authorization_document=make_auth(
                valid_from_claimed="2027-01-01T00:00:00Z"  # after CLAIMED_TIME
            ),
        )
    )
    assert not_yet.reason == "WITNESS_UNAUTHORIZED"


def test_invalid_document_is_unproven_not_crash(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    for bad in [
        make_auth(protocol_version="oev-witness-authorization/9.9"),
        make_auth(valid_from_claimed="not-a-time"),
        make_auth(
            valid_from_claimed="2027-06-01T00:00:00Z", valid_until_claimed="2026-01-01T00:00:00Z"
        ),
        {k: v for k, v in make_auth().items() if k != "authorized_profiles"},
    ]:
        result = verify_historical_execution(hea_inputs(bundle, witness_authorization_document=bad))
        assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
        assert result.reason == "WITNESS_UNAUTHORIZED"


def test_missing_authorization_fails_only_when_required(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    # Default (v0.1 compat): no authorisation supplied, verification still
    # proceeds — but the notes say authorisation was not checked.
    default = verify_historical_execution(hea_inputs(bundle))
    assert default.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert any("authorisation not checked" in n for n in default.notes)
    # Strict mode: the same bundle fails closed.
    strict = verify_historical_execution(hea_inputs(bundle, require_witness_authorization=True))
    assert strict.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert strict.reason == "WITNESS_UNAUTHORIZED"


def test_loader_rejects_malformed_documents() -> None:
    with pytest.raises(ValueError):
        load_witness_authorization_document(make_auth(valid_from_claimed="2026-02-30T00:00:00Z"))
    with pytest.raises(ValueError):
        load_witness_authorization_document({"protocol_version": "oev-witness-authorization/0.1"})
    auth = load_witness_authorization_document(make_auth())
    assert (
        check_witness_authorization(
            auth,
            key_id="wit-1",
            profile_id="strict-conformance-profile",
            check_id="archive_safety",
            claimed_time=CLAIMED_TIME,
        )
        == ""
    )
    assert (
        check_witness_authorization(
            auth,
            key_id="wit-1",
            profile_id="strict-conformance-profile",
            check_id="archive_safety",
            claimed_time="2028-01-01T00:00:00Z",
        )
        != ""
    )

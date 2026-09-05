"""Additional security boundary and hostile input tests for OEVP."""

from typing import Any

import pytest

from oev.canonical import CanonicalizationError, canonicalize_json
from oev.dsse import DsseError, parse_dsse_envelope
from oev.schemas import SchemaValidationError, validate_document


def test_oversized_fields_rejected_by_schema():
    # Schema validation rejects non-string or malformed structures
    with pytest.raises(SchemaValidationError):
        validate_document(
            {
                "receipt_id": 12345,  # Must be string
                "protocol_version": "oev-receipt/0.1",
                "recorded_verification_time": "not-a-date",
            },
            "verification-receipt.schema.json",
        )


def test_malformed_dsse_signatures_array():
    with pytest.raises(DsseError, match="must be a non-empty array"):
        parse_dsse_envelope(
            {
                "payloadType": "application/vnd.oev.verification-receipt+json",
                "payload": "e30=",  # base64 for "{}"
                "signatures": [],
            }
        )


def test_invalid_base64_in_dsse_payload():
    with pytest.raises(DsseError, match="invalid Base64"):
        parse_dsse_envelope(
            {
                "payloadType": "application/vnd.oev.verification-receipt+json",
                "payload": "not-valid-base64---!@#$",
                "signatures": [{"sig": "abcd"}],
            }
        )


def test_extreme_integer_nesting_depth():
    # Deeply nested structure with safe integers succeeds
    current: dict[str, Any] = {"val": 42}
    for _ in range(50):
        current = {"nested": current}
    assert b"42" in canonicalize_json(current)

    # Deeply nested structure with unsafe integer raises
    current_unsafe: dict[str, Any] = {"val": 9007199254740992}
    for _ in range(50):
        current_unsafe = {"nested": current_unsafe}
    with pytest.raises(CanonicalizationError):
        canonicalize_json(current_unsafe)

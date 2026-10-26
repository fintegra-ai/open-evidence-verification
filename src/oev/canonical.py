# SPDX-License-Identifier: Apache-2.0

"""Deterministic JSON Canonicalization Scheme (RFC 8785 / JCS) with integer boundary enforcement.

OEPT security review identified that Python JCS implementations can exhibit unsafe
behavior on large integers beyond standard IEEE 754 double-precision exact representation.
OEVP independently enforces the safe integer domain:
    [-(2^53 - 1), +(2^53 - 1)] = [-9007199254740991, 9007199254740991]

Integers outside this range are rejected prior to canonicalization.
"""

from __future__ import annotations

import json
import math
from typing import Any

import jcs

# IEEE 754 safe integer range for exact representation in JSON / ECMAScript
MAX_SAFE_INTEGER: int = 9007199254740991  # 2**53 - 1
MIN_SAFE_INTEGER: int = -9007199254740991  # -(2**53 - 1)

# Default upper bound for JSON payloads (10 MiB)
MAX_JSON_BYTES: int = 10 * 1024 * 1024


class CanonicalizationError(ValueError):
    """Raised when data cannot be safely or deterministically canonicalized."""


def _no_duplicates_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys during JSON parsing to prevent parser differential attacks."""
    res: dict[str, Any] = {}
    for key, value in pairs:
        if key in res:
            raise ValueError(f"Duplicate JSON object key detected: {key!r}")
        res[key] = value
    return res


def safe_json_loads(data: str | bytes, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse JSON with strict duplicate-key rejection and size bounding."""
    byte_len = len(data.encode("utf-8") if isinstance(data, str) else data)
    if byte_len > max_bytes:
        raise ValueError(
            f"JSON payload exceeds maximum allowed size ({byte_len} > {max_bytes} bytes)"
        )
    return json.loads(data, object_pairs_hook=_no_duplicates_object_pairs_hook)


def check_integer_safety(obj: Any) -> None:
    """Recursively verify that all numbers in obj fall within the safe JCS domain.

    Rejects non-finite floats (NaN, +Infinity, -Infinity) and integers outside
    [MIN_SAFE_INTEGER, MAX_SAFE_INTEGER].
    """
    if isinstance(obj, bool):
        # In Python, bool is a subclass of int. Bools are safe.
        return
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalizationError(
                f"Non-finite float {obj} is not supported in canonical JSON"
            )
        return
    if isinstance(obj, int):
        if obj < MIN_SAFE_INTEGER or obj > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"Integer {obj} is outside safe JCS range [{MIN_SAFE_INTEGER}, {MAX_SAFE_INTEGER}]"
            )
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"JSON object key must be string, got {type(key).__name__}"
                )
            check_integer_safety(value)
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            check_integer_safety(item)
        return


def canonicalize_json(data: Any) -> bytes:
    """Canonicalize a JSON-compatible Python structure according to RFC 8785 (JCS).

    Enforces safe integer and float boundaries and returns UTF-8 encoded canonical bytes.
    """
    check_integer_safety(data)
    try:
        return jcs.canonicalize(data)  # type: ignore[no-any-return]
    except Exception as exc:
        raise CanonicalizationError(f"JCS canonicalization failed: {exc}") from exc

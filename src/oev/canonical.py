"""Deterministic JSON Canonicalization Scheme (RFC 8785 / JCS) with integer boundary enforcement.

OEPT security review identified that Python JCS implementations can exhibit unsafe
behavior on large integers beyond standard IEEE 754 double-precision exact representation.
OEVP independently enforces the safe integer domain:
    [-(2^53 - 1), +(2^53 - 1)] = [-9007199254740991, 9007199254740991]

Integers outside this range are rejected prior to canonicalization.
"""

from __future__ import annotations

from typing import Any
import jcs

# IEEE 754 safe integer range for exact representation in JSON / ECMAScript
MAX_SAFE_INTEGER: int = 9007199254740991  # 2**53 - 1
MIN_SAFE_INTEGER: int = -9007199254740991  # -(2**53 - 1)


class CanonicalizationError(ValueError):
    """Raised when data cannot be safely or deterministically canonicalized."""


def check_integer_safety(obj: Any) -> None:
    """Recursively verify that all integers in obj fall within the safe JCS integer domain."""
    if isinstance(obj, bool):
        # In Python, bool is a subclass of int. Bools are safe.
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
                raise CanonicalizationError(f"JSON object key must be string, got {type(key).__name__}")
            check_integer_safety(value)
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            check_integer_safety(item)
        return


def canonicalize_json(data: Any) -> bytes:
    """Canonicalize a JSON-compatible Python structure according to RFC 8785 (JCS).

    Enforces safe integer boundaries and returns UTF-8 encoded canonical bytes.
    """
    check_integer_safety(data)
    try:
        return jcs.canonicalize(data)  # type: ignore[no-any-return]
    except Exception as exc:
        raise CanonicalizationError(f"JCS canonicalization failed: {exc}") from exc

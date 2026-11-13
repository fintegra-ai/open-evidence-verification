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
MAX_JSON_DEPTH: int = 128


class CanonicalizationError(ValueError):
    """Raised when data cannot be safely or deterministically canonicalized."""


def _check_no_lone_surrogates(value: str, path: str = "$") -> None:
    """Reject unpaired surrogates (RFC 8785 §3.2.2.2) with a stable error.

    A lone surrogate has no UTF-8 encoding; without this check the
    failure surfaces as a codec ``UnicodeEncodeError`` from inside the
    ``jcs`` library. Both failure modes are controlled rejections, but
    this one names the rule that was violated.
    """
    i = 0
    while i < len(value):
        cp = ord(value[i])
        if 0xD800 <= cp <= 0xDBFF:
            nxt = ord(value[i + 1]) if i + 1 < len(value) else -1
            if not 0xDC00 <= nxt <= 0xDFFF:
                raise CanonicalizationError(
                    f"{path}: lone surrogate U+{cp:04X} is not in the canonical domain "
                    "(RFC 8785 §3.2.2.2: unpaired surrogates must terminate with an error)"
                )
            i += 2
            continue
        if 0xDC00 <= cp <= 0xDFFF:
            raise CanonicalizationError(
                f"{path}: lone surrogate U+{cp:04X} is not in the canonical domain "
                "(RFC 8785 §3.2.2.2: unpaired surrogates must terminate with an error)"
            )
        i += 1


def _check_strings_no_lone_surrogates(obj: Any, path: str = "$") -> None:
    """Recursively reject lone surrogates in every string and dict key."""
    if isinstance(obj, str):
        _check_no_lone_surrogates(obj, path)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                _check_no_lone_surrogates(key, f"{path} (key)")
            _check_strings_no_lone_surrogates(value, f"{path}.{key}")
        return
    if isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            _check_strings_no_lone_surrogates(item, f"{path}[{i}]")
        return


def _no_duplicates_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys during JSON parsing to prevent parser differential attacks."""
    res: dict[str, Any] = {}
    for key, value in pairs:
        if key in res:
            raise ValueError(f"Duplicate JSON object key detected: {key!r}")
        res[key] = value
    return res


def _check_json_depth(value: Any) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if not isinstance(current, (dict, list, tuple)):
            continue
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON nesting exceeds the supported depth")
        children = current.values() if isinstance(current, dict) else current
        stack.extend(
            (child, depth + 1) for child in children if isinstance(child, (dict, list, tuple))
        )


def safe_json_loads(data: str | bytes, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse JSON with strict duplicate-key rejection and size bounding.

    Invalid UTF-8, duplicate keys and lone surrogates (RFC 8785 §3.2.2.2)
    all fail as ``ValueError`` — never as a bare codec error and never by
    silently keeping the last duplicate or substituting U+FFFD.
    """
    if isinstance(data, str):
        try:
            byte_len = len(data.encode("utf-8"))
        except UnicodeEncodeError:
            # A str containing lone surrogates cannot be UTF-8 encoded;
            # the surrogate check below rejects it with a stable error.
            byte_len = len(data)
    else:
        byte_len = len(data)
    if byte_len > max_bytes:
        raise ValueError(
            f"JSON payload exceeds maximum allowed size ({byte_len} > {max_bytes} bytes)"
        )
    try:
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"JSON payload is not valid UTF-8: {exc}") from exc
        parsed = json.loads(data, object_pairs_hook=_no_duplicates_object_pairs_hook)
        _check_json_depth(parsed)
        _check_strings_no_lone_surrogates(parsed)
        return parsed
    except ValueError:
        raise
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the supported depth") from exc


def check_integer_safety(obj: Any) -> None:
    """Recursively verify that all numbers in obj fall within the safe JCS domain.

    Rejects non-finite floats (NaN, +Infinity, -Infinity) and integers outside
    [MIN_SAFE_INTEGER, MAX_SAFE_INTEGER]. Finite floats are ACCEPTED and
    serialize per ECMAScript ``Number::toString`` (RFC 8785 §3.2.2.3) —
    round 3 design decision, matching OEPT and the Node verifier.
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
    Finite floats serialize per ECMAScript ``Number::toString`` (RFC 8785
    §3.2.2.3); non-finite floats, out-of-range integers and lone surrogates
    (§3.2.2.2) are rejected with ``CanonicalizationError``.
    """
    try:
        _check_json_depth(data)
        check_integer_safety(data)
        _check_strings_no_lone_surrogates(data)
        return jcs.canonicalize(data)  # type: ignore[no-any-return]
    except CanonicalizationError:
        raise
    except Exception as exc:
        raise CanonicalizationError(f"JCS canonicalization failed: {exc}") from exc

# SPDX-License-Identifier: Apache-2.0

"""Round-3 (P0) JCS convergence tests: float / int / duplicate-key /
unicode / lone-surrogate / malformed-timestamp inputs behave the same
in OEVP, OEPT and (via the differential) the Node verifier.

Float rule (design decision, RFC 8785 §3.2.2.3): finite floats are
ACCEPTED on both sides and serialize per ECMAScript Number::toString.
Non-finite floats, out-of-range integers and lone surrogates (§3.2.2.2)
are rejected with a controlled error on both sides.
"""

from __future__ import annotations

import json

import pytest
from oept.canonical import CanonicalizationError as OeptCanonicalError
from oept.canonical import canonicalize_json as oept_canonicalize

from oev.canonical import CanonicalizationError as OevCanonicalError
from oev.canonical import canonicalize_json as oev_canonicalize
from oev.canonical import safe_json_loads

# (Python value, expected canonical bytes) — ECMAScript Number::toString.
FINITE_FLOAT_CASES = [
    (1.5, b'{"x":1.5}'),
    (-0.5, b'{"x":-0.5}'),
    (1e21, b'{"x":1e+21}'),
    (1e20, b'{"x":100000000000000000000}'),
    (1e-7, b'{"x":1e-7}'),
    (0.1, b'{"x":0.1}'),
    (0.30000000000000004, b'{"x":0.30000000000000004}'),
    (5e-324, b'{"x":5e-324}'),
    (1.7976931348623157e308, b'{"x":1.7976931348623157e+308}'),
    (2.2250738585072014e-308, b'{"x":2.2250738585072014e-308}'),
    (-0.0, b'{"x":0}'),
    (1.0, b'{"x":1}'),
    (123456789.123456789, b'{"x":123456789.12345679}'),
    (1e100, b'{"x":1e+100}'),
    (2.5e-10, b'{"x":2.5e-10}'),
    (0.000001, b'{"x":0.000001}'),
    (0.0000001, b'{"x":1e-7}'),
]


@pytest.mark.parametrize("value,expected", FINITE_FLOAT_CASES)
def test_finite_floats_canonicalize_identically(value: float, expected: bytes) -> None:
    assert oev_canonicalize({"x": value}) == expected
    assert oept_canonicalize({"x": value}) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('{"x":1.5}', b'{"x":1.5}'),
        ('{"x":1e21}', b'{"x":1e+21}'),
        ('{"x":1.0}', b'{"x":1}'),
        ('{"x":1e-999}', b'{"x":0}'),  # underflows to zero, both sides
        ('{"x":-0}', b'{"x":0}'),
        ("[1e100,1e-100,123.456e7]", b"[1e+100,1e-100,1234560000]"),
    ],
)
def test_float_lexemes_from_json_text(raw: str, expected: bytes) -> None:
    assert oev_canonicalize(safe_json_loads(raw)) == expected
    assert oept_canonicalize(json.loads(raw)) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_rejected_both_sides(value: float) -> None:
    with pytest.raises(OevCanonicalError):
        oev_canonicalize({"x": value})
    with pytest.raises(OeptCanonicalError):
        oept_canonicalize({"x": value})


@pytest.mark.parametrize("raw", ['{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}'])
def test_non_finite_float_literals_rejected(raw: str) -> None:
    # Python's json accepts NaN/Infinity literals; canonicalization must not.
    with pytest.raises(OevCanonicalError):
        oev_canonicalize(safe_json_loads(raw))
    with pytest.raises(OeptCanonicalError):
        oept_canonicalize(json.loads(raw))


@pytest.mark.parametrize("raw", ['{"x":1e999}', '{"x":-1e999}'])
def test_overflow_float_literals_rejected(raw: str) -> None:
    with pytest.raises(OevCanonicalError):
        oev_canonicalize(safe_json_loads(raw))
    with pytest.raises(OeptCanonicalError):
        oept_canonicalize(json.loads(raw))


@pytest.mark.parametrize(
    "value,expected",
    [
        (2**53 - 1, b'{"x":9007199254740991}'),
        (-(2**53 - 1), b'{"x":-9007199254740991}'),
        (0, b'{"x":0}'),
    ],
)
def test_safe_integers_ok_both_sides(value: int, expected: bytes) -> None:
    assert oev_canonicalize({"x": value}) == expected
    assert oept_canonicalize({"x": value}) == expected


@pytest.mark.parametrize("value", [2**53, -(2**53), 10**21, 2**63 - 1, -(2**63)])
def test_out_of_range_integers_rejected_both_sides(value: int) -> None:
    with pytest.raises(OevCanonicalError):
        oev_canonicalize({"x": value})
    with pytest.raises(OeptCanonicalError):
        oept_canonicalize({"x": value})


@pytest.mark.parametrize(
    "raw",
    [
        '{"a":1,"a":2}',
        '{"a":{"b":1,"b":2}}',
        '[{"x":1,"x":2}]',
    ],
)
def test_duplicate_keys_rejected_at_parse(raw: str) -> None:
    with pytest.raises(ValueError, match="uplicate"):
        safe_json_loads(raw)


def test_duplicate_keys_rejected_by_oept_manifest_parser() -> None:
    from oept.verify import _loads_manifest, _ManifestParseError

    with pytest.raises(_ManifestParseError, match="uplicate"):
        _loads_manifest(b'{"a":1,"a":2}')


def test_duplicate_keys_rejected_by_oept_trust_keys_loader(tmp_path) -> None:
    from oept.errors import ConfigurationError
    from oept.signing import load_trust_keys

    path = tmp_path / "keys.json"
    path.write_text('[{"key_id":"k1","public_key_pem":"x","public_key_pem":"y"}]', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="uplicate"):
        load_trust_keys(path)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (r'"hello"', b'"hello"'),
        (r'"\u0000\u001f\u007f"', b'"\\u0000\\u001f\x7f"'),
        (r'"\ud800\udc00"', '"\U00010000"'.encode("utf-8")),
        (r'"\ud83d\ude00"', '"😀"'.encode()),
        (r'"\u2028\u2029"', '"  "'.encode()),
        (r'"\u00a0"', '" "'.encode()),
        (r'"a/b"', b'"a/b"'),
        (r'"\""', b'"\\""'),
        (r'"\\"', b'"\\\\"'),
        (r'"\b\t\n\f\r"', b'"\\b\\t\\n\\f\\r"'),
        (r'"caf\u00e9"', '"café"'.encode()),
        (r'"\u00e9\u4e2d\ud83d\ude00"', '"é中😀"'.encode()),
        ('{"b":1,"a":2}', b'{"a":2,"b":1}'),
        ('{"\\u00e9":1,"e":2}', '{"e":2,"é":1}'.encode()),
    ],
)
def test_unicode_strings_canonicalize_identically(raw: str, expected: bytes) -> None:
    assert oev_canonicalize(safe_json_loads(raw)) == expected
    assert oept_canonicalize(json.loads(raw)) == expected


@pytest.mark.parametrize(
    "raw",
    [
        r'"\ud800"',
        r'"\udc00"',
        r'"a\ud800b"',
        r'{"\ud800key":1}',
        r'{"key\udc00":1}',
        r'"\ud800\ud800"',
        r'"\udc00\ud800"',
    ],
)
def test_lone_surrogates_rejected_both_sides(raw: str) -> None:
    with pytest.raises(ValueError, match="lone surrogate"):
        safe_json_loads(raw)
    with pytest.raises(OevCanonicalError, match="lone surrogate"):
        oev_canonicalize(json.loads(raw))
    with pytest.raises(OeptCanonicalError, match="lone surrogate"):
        oept_canonicalize(json.loads(raw))


@pytest.mark.parametrize(
    "data",
    [b'{"a":"\xff"}', b'{"a":1}\xff', b"\xff\xfe{}", b'{"a":"\xc3\x28"}'],
)
def test_invalid_utf8_rejected_as_value_error(data: bytes) -> None:
    with pytest.raises(ValueError):
        safe_json_loads(data)
    # No bare UnicodeDecodeError may escape the strict parser: the raised
    # error must be a plain ValueError, not the codec subclass.
    with pytest.raises(ValueError) as excinfo:
        safe_json_loads(data)
    assert type(excinfo.value) is ValueError


def test_lone_surrogate_in_plain_string_rejected() -> None:
    with pytest.raises(OevCanonicalError, match="lone surrogate"):
        oev_canonicalize({"a": "x\ud800y"})
    with pytest.raises(OeptCanonicalError, match="lone surrogate"):
        oept_canonicalize({"a": "x\ud800y"})

# SPDX-License-Identifier: Apache-2.0

"""Trusted timestamping for HEA — RFC 3161 request format + mock TSA (v0.2, optional).

HEA design §9.4: ``claimed_time`` is self-asserted and proves nothing
about wall-clock time. This module adds the *optional* trusted-time leg:

* :func:`build_timestamp_request` encodes an RFC 3161 ``TimeStampReq``
  (DER, ``messageImprint`` = SHA-256 of the attested digest) with a
  minimal hand-rolled DER encoder/decoder — no ASN.1 dependency, no
  network use anywhere in this module.
* :class:`MockTSA` is a *local, offline stand-in* for a real TSA. It
  signs a timestamp token (DSSE envelope,
  ``application/vnd.oev.timestamp-token+json``) binding the imprint
  digest to a ``tsa_gen_time``. The mock TSA's clock is whatever the
  caller supplies — it is NOT a trusted time source, and the token
  says so (``tsa_policy: "mock-tsa/0.1"``).
* :func:`verify_timestamp_token` checks a token offline against
  caller-supplied TSA trust roots: DSSE signature, imprint digest
  equality with the attested object digest, and parseable gen-time.
  It returns ``TSA_VERIFIED`` / ``TSA_INVALID`` / ``UNVERIFIED``
  (no token at all). A token proves *at most* that the attested
  digest existed no later than ``tsa_gen_time`` and has not changed
  since — it does NOT prove the execution happened at that time
  (the execution↔token gap still rests on witness honesty, design §9.4).

``claimed_time`` (witness claim, in the attestation) and ``tsa_gen_time``
(TSA claim, in the token) are kept as separate fields everywhere and are
reported separately; they are never merged into one "timestamp".

What this module does NOT do (honest limits):
* No network call to a real TSA (``http``/``socket`` are never imported).
* No CMS / SignedData parsing: a real RFC 3161 ``TimeStampToken`` is a
  CMS SignedData object. This module's token is a DSSE-wrapped record
  carrying the RFC 3161 *request* bytes; full CMS token verification
  against a production TSA is future work and is NOT claimed here.
* A mock-TSA token is not trusted time. Any verifier output that
  carries only a mock token MUST still report time as not proven
  against a real TSA (``timestamp_status`` distinguishes
  ``TSA_VERIFIED (mock)`` from a production TSA).
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize_json, safe_json_loads
from .dsse import DsseError, build_dsse_envelope, parse_dsse_envelope
from .hashing import is_valid_digest, sha256_bytes
from .signing import load_ed25519_private_key, verify_dsse_signature_with_key

TSA_TOKEN_PROTOCOL_VERSION = "oev-tsa-token/0.1"
TSA_TOKEN_PAYLOAD_TYPE = "application/vnd.oev.timestamp-token+json"
MOCK_TSA_POLICY = "mock-tsa/0.1"

#: DER encoding of the SHA-256 AlgorithmIdentifier (OID 2.16.840.1.101.3.4.2.1 + NULL).
_SHA256_ALG_ID_DER = bytes.fromhex("300d06096086480165030402010500")
#: Content bytes of that AlgorithmIdentifier SEQUENCE (what _read_tlv returns).
_SHA256_ALG_ID_CONTENT = bytes.fromhex("06096086480165030402010500")


# -- minimal DER ------------------------------------------------------------


def _der_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return body


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at ``offset``. Returns ``(tag, content, next_offset)``."""
    if offset >= len(data):
        raise ValueError("DER: truncated input")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("DER: truncated length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0 or offset + nbytes > len(data):
            raise ValueError("DER: bad long-form length")
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    else:
        length = first
    if offset + length > len(data):
        raise ValueError("DER: truncated content")
    return tag, data[offset : offset + length], offset + length


def build_timestamp_request(digest: str, nonce: int | None = None) -> tuple[bytes, int]:
    """Build an RFC 3161 ``TimeStampReq`` (DER) for a SHA-256 digest.

    Structure (RFC 3161 §2.4.1)::

        TimeStampReq ::= SEQUENCE {
            version        INTEGER { v1(1) },
            messageImprint SEQUENCE {
                hashAlgorithm AlgorithmIdentifier (SHA-256),
                hashedMessage OCTET STRING (32 bytes) },
            nonce          INTEGER OPTIONAL,
            certReq        BOOLEAN DEFAULT FALSE }

    (The nonce is a plain INTEGER — see the TUR 4 note in
    :func:`build_timestamp_request`.)

    ``nonce`` is generated fresh (128-bit) when omitted, so two requests
    for the same digest differ. Returns ``(der_bytes, nonce)``.
    No network is involved: this only *encodes* the request a real TSA
    client would send.

    TUR 4 correction (2026-11-13, measured against live TSAs and
    OpenSSL 3.0.13, and checked against the RFC 3161 text itself):
    the nonce is a *plain* ``INTEGER`` (tag ``0x02``) in
    ``TimeStampReq`` — there is NO ``[1]`` tag on it. The Tur-3
    docstring claimed ``[1] IMPLICIT INTEGER``; that was wrong, and
    the first TUR 4 attempt (primitive context tag ``0x81``) was wrong
    too. Evidence: OpenSSL's ``TS_REQ`` template is
    ``ASN1_OPT(nonce, ASN1_INTEGER)`` and its responder rejects every
    ``[1]``-tagged nonce ("Field=extensions, wrong tag"); DigiCert
    merely *tolerates* a ``[1]`` nonce by ignoring it (grants, but the
    token carries no nonce); freetsa.org rejects it outright (PKIStatus
    2). The parser below accepts the correct ``0x02`` form and still
    accepts the legacy ``0x81``/``0xA1`` bytes so mock tokens minted
    before this fix keep verifying.
    """
    if not is_valid_digest(digest):
        raise ValueError(f"Invalid digest for timestamp request: {digest!r}")
    raw = bytes.fromhex(digest[len("sha256:") :])
    if nonce is None:
        nonce = secrets.randbits(128)
    if nonce < 0:
        raise ValueError("Timestamp request nonce must be non-negative")
    message_imprint = _der_tlv(0x30, _SHA256_ALG_ID_DER + _der_tlv(0x04, raw))
    version = _der_tlv(0x02, b"\x01")
    # Plain INTEGER (tag 0x02) — RFC 3161 §2.4.1; see docstring.
    nonce_tlv = _der_tlv(0x02, _der_integer_bytes(nonce))
    cert_req = _der_tlv(0x01, b"\x00")
    body = version + message_imprint + nonce_tlv + cert_req
    return _der_tlv(0x30, body), nonce


def parse_timestamp_request(der: bytes) -> dict[str, Any]:
    """Parse and validate a DER ``TimeStampReq`` built by :func:`build_timestamp_request`.

    Returns ``{"version": 1, "hash_algorithm": "sha256", "digest": "sha256:…",
    "nonce": int, "cert_req": bool}``. Raises ValueError on any structural
    deviation — a malformed request is never silently accepted.
    """
    tag, body, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("DER: TimeStampReq must be a single SEQUENCE")
    offset = 0
    tag, version_bytes, offset = _read_tlv(body, offset)
    if tag != 0x02 or int.from_bytes(version_bytes, "big") != 1:
        raise ValueError("DER: TimeStampReq version must be INTEGER 1")
    tag, imprint, offset = _read_tlv(body, offset)
    if tag != 0x30:
        raise ValueError("DER: messageImprint must be a SEQUENCE")
    itag, alg_id, ioff = _read_tlv(imprint, 0)
    if itag != 0x30 or alg_id != _SHA256_ALG_ID_CONTENT:
        raise ValueError("DER: messageImprint hashAlgorithm must be SHA-256")
    itag, hashed, ioff = _read_tlv(imprint, ioff)
    if itag != 0x04 or len(hashed) != 32 or ioff != len(imprint):
        raise ValueError("DER: hashedMessage must be a 32-byte OCTET STRING")
    digest = "sha256:" + hashed.hex()
    nonce: int | None = None
    cert_req = False
    while offset < len(body):
        tag, content, offset = _read_tlv(body, offset)
        if tag in (0x02, 0x81, 0xA1):
            # 0x02 is the correct plain-INTEGER tag; 0x81/0xA1 are
            # accepted for tokens minted by pre-TUR-4 encoders
            # (see build_timestamp_request docstring).
            nonce = int.from_bytes(content, "big")
        elif tag == 0x01:
            if len(content) != 1:
                raise ValueError("DER: certReq must be one byte")
            cert_req = content != b"\x00"
        else:
            raise ValueError(f"DER: unexpected TimeStampReq field tag 0x{tag:02x}")
    if nonce is None:
        raise ValueError("DER: TimeStampReq nonce is required by this implementation")
    return {
        "version": 1,
        "hash_algorithm": "sha256",
        "digest": digest,
        "nonce": nonce,
        "cert_req": cert_req,
    }


# -- timestamp token ----------------------------------------------------------


@dataclass(frozen=True)
class TimestampToken:
    """A TSA-issued timestamp token (DSSE-wrapped, ``oev-tsa-token/0.1``).

    ``tsa_gen_time`` is the TSA's claimed generation time — a *different*
    field from the attestation's ``claimed_time``. The two are never
    merged. ``request_der_b64`` carries the RFC 3161 request bytes that
    were (or, for the mock TSA, would be) sent, so the imprint can be
    re-checked against the request itself.
    """

    protocol_version: str
    imprint_digest: str
    token_digest: str
    tsa_gen_time: str
    tsa_key_id: str
    nonce: int
    request_der_b64: str
    tsa_policy: str = MOCK_TSA_POLICY

    def to_dict(self) -> dict[str, Any]:
        # Nonce is a 128-bit integer — outside the JCS safe-integer range —
        # so it is serialised as a decimal string, never as a JSON number.
        return {
            "protocol_version": self.protocol_version,
            "imprint_digest": self.imprint_digest,
            "token_digest": self.token_digest,
            "tsa_gen_time": self.tsa_gen_time,
            "tsa_key_id": self.tsa_key_id,
            "nonce": str(self.nonce),
            "request_der_b64": self.request_der_b64,
            "tsa_policy": self.tsa_policy,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimestampToken:
        if str(data.get("protocol_version", "")) != TSA_TOKEN_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported timestamp token version: {data.get('protocol_version')!r}"
            )
        for field in ("imprint_digest", "token_digest"):
            if not is_valid_digest(str(data.get(field, ""))):
                raise ValueError(f"Timestamp token {field} is malformed")
        return cls(
            protocol_version=TSA_TOKEN_PROTOCOL_VERSION,
            imprint_digest=str(data["imprint_digest"]),
            token_digest=str(data["token_digest"]),
            tsa_gen_time=str(data["tsa_gen_time"]),
            tsa_key_id=str(data["tsa_key_id"]),
            nonce=int(data["nonce"]),
            request_der_b64=str(data["request_der_b64"]),
            tsa_policy=str(data.get("tsa_policy", MOCK_TSA_POLICY)),
        )


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MockTSA:
    """Local offline stand-in for an RFC 3161 TSA.

    ``timestamp(digest, gen_time)`` builds the RFC 3161 request DER,
    then signs a :class:`TimestampToken` binding the imprint digest to
    ``gen_time``. ``gen_time`` is caller-supplied (tests pass an
    explicit value); when omitted it defaults to the local clock — in
    either case it is the *mock TSA's claim*, not trusted wall-clock
    time, and the token's ``tsa_policy`` says so. A mock token must
    never be presented as a production-TSA timestamp.
    """

    def __init__(self, private_key_pem: bytes, key_id: str) -> None:
        self._private_key_pem = bytes(private_key_pem)
        self.key_id = key_id
        # Fail fast on an unusable key (same rule as the witness keys).
        load_ed25519_private_key(self._private_key_pem)

    def timestamp(self, digest: str, gen_time: str | None = None) -> dict[str, Any]:
        """Stamp ``digest``. Returns ``{"token": ..., "envelope": ...}``."""
        gen_time = gen_time or _utc_now_iso()
        request_der, nonce = build_timestamp_request(digest)
        token = TimestampToken(
            protocol_version=TSA_TOKEN_PROTOCOL_VERSION,
            imprint_digest=digest,
            token_digest=digest,
            tsa_gen_time=gen_time,
            tsa_key_id=self.key_id,
            nonce=nonce,
            request_der_b64=base64.b64encode(request_der).decode("ascii"),
            tsa_policy=MOCK_TSA_POLICY,
        )
        payload_bytes = canonicalize_json(token.to_dict())
        private_key = load_ed25519_private_key(self._private_key_pem)
        from .dsse import compute_pae

        raw_sig = private_key.sign(compute_pae(TSA_TOKEN_PAYLOAD_TYPE, payload_bytes))
        sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
        if self.key_id:
            sig_entry["keyid"] = self.key_id
        envelope = build_dsse_envelope(
            payload_type=TSA_TOKEN_PAYLOAD_TYPE,
            payload_bytes=payload_bytes,
            signatures=[sig_entry],
        )
        return {"token": token.to_dict(), "envelope": envelope}


def parse_timestamp_token_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Parse a DSSE timestamp-token envelope into its payload dict (no trust check)."""
    payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    if payload_type != TSA_TOKEN_PAYLOAD_TYPE:
        raise DsseError(f"Unexpected DSSE payloadType for a timestamp token: {payload_type!r}")
    data = safe_json_loads(payload_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise DsseError("Timestamp token payload is not a JSON object")
    return data


def verify_timestamp_token(
    envelope: dict[str, Any] | None,
    expected_digest: str,
    tsa_trust_store: Any | None,
) -> tuple[str, str]:
    """Verify a timestamp token offline.

    Returns ``(status, note)`` with status one of:

    * ``UNVERIFIED`` — no token was supplied (or no TSA trust store).
      This is NOT a failure: a missing token means "time not proven",
      exactly like v0.1 ``claimed_time``.
    * ``TSA_VERIFIED`` — the token's DSSE signature verifies under a
      caller-trusted TSA key, the imprint digest equals
      ``expected_digest``, and the embedded RFC 3161 request parses
      and carries the same digest and nonce. The note records whether
      the token came from the mock TSA (``mock-tsa/0.1``) — mock tokens
      are verified as *mock* tokens, never as production timestamps.
    * ``TSA_INVALID`` — any check failed. The token must be treated as
      absent; the execution time stays unproven.
    """
    if envelope is None:
        return "UNVERIFIED", "No timestamp token supplied; time is not proven."
    if tsa_trust_store is None or len(getattr(tsa_trust_store, "keys", [])) == 0:
        return "UNVERIFIED", "No TSA trust store supplied; token cannot be checked."
    try:
        payload = parse_timestamp_token_envelope(envelope)
        token = TimestampToken.from_dict(payload)
    except (DsseError, ValueError) as exc:
        return "TSA_INVALID", f"Timestamp token does not parse: {exc}"
    if token.imprint_digest != expected_digest or token.token_digest != expected_digest:
        return (
            "TSA_INVALID",
            "Timestamp token imprint does not match the attested digest.",
        )
    try:
        request = parse_timestamp_request(base64.b64decode(token.request_der_b64, validate=True))
    except ValueError as exc:
        return "TSA_INVALID", f"Embedded RFC 3161 request does not parse: {exc}"
    if request["digest"] != expected_digest or int(request["nonce"]) != int(token.nonce):
        return "TSA_INVALID", "Embedded RFC 3161 request disagrees with the token."
    from datetime import datetime

    try:
        datetime.strptime(token.tsa_gen_time, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return "TSA_INVALID", "Token tsa_gen_time is not a valid UTC timestamp."
    for trusted_key in tsa_trust_store.keys:
        if trusted_key.key_id != token.tsa_key_id:
            continue
        if verify_dsse_signature_with_key(envelope, trusted_key.public_key_pem):
            origin = (
                "mock TSA (NOT production trusted time)"
                if token.tsa_policy == MOCK_TSA_POLICY
                else f"TSA policy {token.tsa_policy}"
            )
            return (
                "TSA_VERIFIED",
                (
                    f"Token signature valid under trusted TSA key {token.tsa_key_id!r} "
                    f"({origin}); tsa_gen_time={token.tsa_gen_time}. "
                    "Proves at most that the digest existed by tsa_gen_time."
                ),
            )
    return "TSA_INVALID", "Token signature does not verify under any trusted TSA key."


def timestamp_token_digest(token: dict[str, Any]) -> str:
    """SHA-256 (JCS) of a timestamp-token payload — for sidecar binding."""
    return sha256_bytes(canonicalize_json(token))

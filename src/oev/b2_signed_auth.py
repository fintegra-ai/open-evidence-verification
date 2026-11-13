# SPDX-License-Identifier: Apache-2.0

"""Signed witness authorisations for Model B2 (round 4, worker D).

Round 3 left the witness-authorisation document unsigned (v0.1):
whoever could hand the verifier a document could authorise any key.
A signed authorisation closes that hole for B2 deployments:

* the operator that owns the witness key (the *issuer*) DSSE-signs
  the ``oev-witness-authorization/0.1`` document with its issuer key;
* the verifier (``b2_verify``) and the B2 runner accept a signed
  authorisation only when the signature verifies against a
  caller-supplied issuer trust store **and** the envelope's ``keyid``
  matches the document's ``issuer_key_id``;
* an unsigned document is rejected whenever the caller requires
  signed authorisation (``require_signed_authorization=True``) — the
  B2 default for new deployments. The unsigned path is kept only for
  backwards compatibility with existing Model A bundles and must be
  explicitly opted into by *not* setting the requirement.

Semantics inherited from ``witness_authorization`` (unchanged):
authorised profiles / checks, validity window in claimed time,
``revoked: true`` authorises nothing. The signature adds *authenticity*
of the document, not new semantics — a signed document that authorises
the wrong profile still fails closed as ``WITNESS_UNAUTHORIZED``.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize_json, safe_json_loads
from .dsse import build_dsse_envelope, compute_pae, parse_dsse_envelope
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .trust import TrustStore
from .witness_authorization import (
    WitnessAuthorization,
    load_witness_authorization_document,
)

SIGNED_AUTHORIZATION_PAYLOAD_TYPE = "application/vnd.oev.witness-authorization+json"


def sign_witness_authorization(
    document: dict[str, Any],
    issuer_private_key_pem: bytes,
    issuer_key_id: str = "",
) -> dict[str, Any]:
    """DSSE-sign a witness-authorisation document with the issuer key.

    The document is schema-validated first; an invalid document is
    never signed. ``issuer_key_id`` (when given) must equal the
    document's ``issuer_key_id``.
    """
    auth = load_witness_authorization_document(document)
    if issuer_key_id and issuer_key_id != auth.issuer_key_id:
        raise ValueError(
            f"Signer key id {issuer_key_id!r} != document issuer_key_id {auth.issuer_key_id!r}"
        )
    payload_bytes = canonicalize_json(document)
    private_key = load_ed25519_private_key(issuer_private_key_pem)
    raw_sig = private_key.sign(compute_pae(SIGNED_AUTHORIZATION_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
    sig_entry["keyid"] = issuer_key_id or auth.issuer_key_id
    return build_dsse_envelope(
        payload_type=SIGNED_AUTHORIZATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_signed_witness_authorization(
    envelope: dict[str, Any] | None,
    issuer_trust_store: TrustStore | None,
    *,
    expected_witness_public_key_digest: str | None = None,
) -> tuple[WitnessAuthorization | None, bool, str]:
    """Verify a signed authorisation envelope.

    Returns ``(authorization|None, ok, note)``. ``ok`` is False for a
    missing envelope, a wrong payload type, an invalid document, an
    untrusted signature, a ``keyid``/``issuer_key_id`` mismatch, or a
    ``witness_public_key_digest`` mismatch. Never raises for a bad
    envelope.
    """
    if envelope is None:
        return None, False, "no signed witness authorisation supplied"
    try:
        payload_type, payload_bytes, signatures = parse_dsse_envelope(envelope)
    except ValueError as exc:
        return None, False, f"signed authorisation envelope malformed: {exc}"
    if payload_type != SIGNED_AUTHORIZATION_PAYLOAD_TYPE:
        return None, False, f"unexpected authorisation payloadType: {payload_type!r}"
    try:
        data = safe_json_loads(payload_bytes.decode("utf-8"))
    except ValueError as exc:
        return None, False, f"authorisation payload is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, False, "authorisation payload is not a JSON object"
    try:
        auth = load_witness_authorization_document(data)
    except ValueError as exc:
        return None, False, f"authorisation document invalid: {exc}"
    if issuer_trust_store is None or len(issuer_trust_store.keys) == 0:
        return auth, False, "no authorisation-issuer trust roots supplied"
    hinted = {s.get("keyid", "") for s in signatures}
    if auth.issuer_key_id not in hinted:
        return (
            auth,
            False,
            (f"authorisation envelope keyid does not name the issuer {auth.issuer_key_id!r}"),
        )
    pae = compute_pae(payload_type, payload_bytes)
    for trusted_key in issuer_trust_store.keys:
        if trusted_key.key_id != auth.issuer_key_id:
            continue
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
        except ValueError:
            continue
        for sig_entry in signatures:
            try:
                public_key.verify(
                    base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                )
                if (
                    expected_witness_public_key_digest is not None
                    and auth.witness_public_key_digest is not None
                    and auth.witness_public_key_digest != expected_witness_public_key_digest
                ):
                    return (
                        auth,
                        False,
                        ("authorisation witness_public_key_digest does not match the witness key"),
                    )
                return auth, True, "signed witness authorisation verified"
            except (InvalidSignature, ValueError):
                continue
    return auth, False, "signed authorisation signature is not trusted by caller"


def signed_authorization_to_document(
    envelope: dict[str, Any],
) -> dict[str, Any]:
    """Extract the plain authorisation document from a signed envelope
    (no trust check — use only after :func:`verify_signed_witness_authorization`)."""
    _payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    data = safe_json_loads(payload_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("authorisation payload is not a JSON object")  # noqa: TRY004
    return data


__all__ = [
    "SIGNED_AUTHORIZATION_PAYLOAD_TYPE",
    "sign_witness_authorization",
    "signed_authorization_to_document",
    "verify_signed_witness_authorization",
]

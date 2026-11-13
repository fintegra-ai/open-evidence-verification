# SPDX-License-Identifier: Apache-2.0

"""Model B2 — separate-machine, re-executing witness (HEA design §2.3, v0.2).

Difference from Model A (``witness.py``): a Model A witness *observes*
the producer's outputs (digests of files the producer wrote, results
the producer reported). A Model B2 witness does not take the producer's
word for anything it can check itself:

1. The witness receives the bundle bytes and the profile bytes itself
   (over the producer↔witness channel) and computes their digests.
2. The witness issues the pre-binding commitment with its own fresh nonce.
3. The witness **re-executes the checks itself**
   (``engine.execute_verification`` on the bytes it received) and
   compares its own per-check results with the producer's claimed
   results (status + detail; ``duration_ms`` is timing, not a result,
   and is excluded from the comparison).
4. The witness signs a per-check attestation ONLY for checks where its
   own re-execution agrees with the producer's claim. A disagreement
   refuses the attestation (fail-closed) — a fake PASS can no longer
   be laundered through a witness signature.

Role separation is enforced in code, not by convention
(HEA design §9.2):
* the witness key, the checkpoint-signer key and the producer's
  receipt-signing key must be three *different* keys (public-key
  digests compared at construction / run time; equal keys raise);
* the witness key must carry role ``witness`` in the caller trust
  store, the checkpoint key role ``checkpoint-signer``;
* a witness authorisation document (``oev-witness-authorization/0.1``,
  see :func:`validate_witness_authorization`) states which profiles
  and bundle formats this witness key may attest; anything outside it
  is refused by the verifier (``WITNESS_UNAUTHORIZED``).

Isolation actually achieved here (prototype — read this before citing
it): separate process, separate venv, separate key material, separate
working directory and separate log file. What is NOT achieved: physical
or administrative independence. In this prototype both venvs install
the same local source tree, so the code digests agree *because the
source is shared*; a production B2 deployment needs independently
managed witness hosts, an authenticated channel (mTLS or signed event
stream — the in-process byte handoff used here is a prototype stand-in,
not a channel), and independent key custody. Every B2 manifest records
this with ``isolation_claim: "prototype-process-venv-key-workdir-only"``
and the limitation ``B2_PROTOTYPE_ISOLATION``. Claiming physical
independence for this prototype would be false.

Honest limits (same as the design doc, now measured in the benchmark):
* A compromised witness (key stolen, operator dishonest) can still
  sign false attestations — B2 moves the trust from the producer's
  machine to the witness's machine, it does not eliminate trust.
* If producer and witness run the same buggy code, a wrong result is
  "confirmed" by agreement (common-mode failure, §0.2).
* B2 receives the bundle bytes, so it is an exposure channel for
  confidential packages (design §9.5): do not use B2 for them.
* No hardware assurance: B2 is not a TEE (Model C).
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, TypeVar

from cryptography.hazmat.primitives import serialization

from . import __version__ as _OEV_VERSION
from .attestation import compute_attestation_digest
from .b2_completeness import build_execution_completeness, sign_execution_completeness
from .b2_signed_auth import verify_signed_witness_authorization
from .canonical import canonicalize_json
from .code_digest import build_code_digest_document, build_environment_record
from .engine import execute_verification, utc_now_iso
from .execution import build_prebinding, compute_code_digest, compute_trust_inputs_digest
from .execution_log import LogCheckpoint, events_from_jsonl, merkle_inclusion_proof
from .hashing import sha256_bytes
from .models import CHECK_STATUS_EXECUTED, CheckStatus, OverallResult, VerificationProfile
from .profiles import compute_profile_digest, load_profile
from .receipts import finalize_receipt
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .witness import (
    WitnessService,
    build_attestation_payload,
    check_private_key_not_test_only,
)

B2_WITNESS_MODE = "separate-machine"
B2_WITNESS_SOFTWARE = "oev-witness-b2 0.1.0"
B2_AUTHORIZATION_PROTOCOL_VERSION = "oev-witness-authorization/0.1"

MODEL_B2_LIMITATIONS: list[dict[str, Any]] = [
    {
        "code": "WITNESS_SEPARATE_MACHINE_REEXECUTING",
        "description": (
            "Re-executing witness: checks were run independently by the "
            "witness on the bundle bytes it received, and attested only "
            "where the witness result agreed with the producer claim. "
            "Protects against a malicious producer on its own machine; "
            "does NOT protect against witness compromise, a dishonest "
            "witness operator, common-mode code faults, or hardware attacks."
        ),
        "material": True,
    },
    {
        "code": "B2_PROTOTYPE_ISOLATION",
        "description": (
            "Prototype isolation only: separate process, venv, keys and "
            "working directory. NO physical or administrative independence "
            "is claimed; both sides install the same local source tree and "
            "the byte handoff is an in-process call, not an authenticated "
            "network channel."
        ),
        "material": True,
    },
    {
        "code": "TIME_NOT_PROVEN",
        "description": "claimed_time is self-asserted; ordering comes from log sequence only.",
        "material": True,
    },
    {
        "code": "NO_HARDWARE_ASSURANCE",
        "description": "No TEE / hardware attestation (Model C not built).",
        "material": True,
    },
]

_B2T = TypeVar("_B2T", bound="B2ProcessWitness")


MODEL_B2_LIMITATIONS_MTLS: list[dict[str, Any]] = [
    (
        {
            "code": "B2_MTLS_SAME_HOST",
            "description": (
                "Same host, separate trust domain: separate process, venv, "
                "keystore and mutually-authenticated TLS channel. NO physical "
                "or administrative independence is claimed; a host-level "
                "attacker defeats this deployment."
            ),
            "material": True,
        }
        if lim["code"] == "B2_PROTOTYPE_ISOLATION"
        else dict(lim)
    )
    for lim in MODEL_B2_LIMITATIONS
]


def limitations_for_channel(channel: str | None) -> list[dict[str, Any]]:
    """Attestation limitations for a witness channel.

    The stdio-pipe prototype keeps the round-3 ``B2_PROTOTYPE_ISOLATION``
    entry; an mTLS channel replaces it with ``B2_MTLS_SAME_HOST``
    (same-host honesty is preserved — only the transport claim changes).
    """
    if channel in ("mtls-tls13-localhost", "mtls"):
        return [dict(lim) for lim in MODEL_B2_LIMITATIONS_MTLS]
    return [dict(lim) for lim in MODEL_B2_LIMITATIONS]


# -- witness authorisation (oev-witness-authorization/0.1) --------------------
#
# This fills design Ek B open question 3 for the B2 witness. Format::
#
#     {
#       "protocol_version": "oev-witness-authorization/0.1",
#       "witness_key_id": "wit-b2-1",
#       "witness_mode": "separate-machine",
#       "profiles": ["strict-conformance-profile"],
#       "bundle_formats": ["oept-bundle/0.1"],
#       "not_after": "2027-12-31T23:59:59Z"
#     }
#
# It converts losslessly to the verifier's ``witness_authorization``
# input (``{key_id: {"profiles": [...]}}`` — ``hea_verifier.py`` Step 4
# reads only ``profiles``; ``bundle_formats`` is enforced here, at
# attestation time, by the B2 witness itself).


def validate_witness_authorization(doc: dict[str, Any]) -> dict[str, Any]:
    """Validate a witness-authorisation document. Raises ValueError."""
    if not isinstance(doc, dict):
        raise TypeError("Witness authorisation must be a JSON object")
    if str(doc.get("protocol_version", "")) != B2_AUTHORIZATION_PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported witness authorisation version: {doc.get('protocol_version')!r}"
        )
    key_id = str(doc.get("witness_key_id", "")).strip()
    if not key_id:
        raise ValueError("Witness authorisation requires a witness_key_id")
    if str(doc.get("witness_mode", B2_WITNESS_MODE)) != B2_WITNESS_MODE:
        raise ValueError("Witness authorisation witness_mode must be 'separate-machine'")
    profiles = doc.get("profiles", [])
    formats = doc.get("bundle_formats", [])
    if (
        not isinstance(profiles, list)
        or not profiles
        or not all(isinstance(p, str) and p for p in profiles)
    ):
        raise ValueError("Witness authorisation requires a non-empty profiles list")
    if not isinstance(formats, list) or not all(isinstance(f, str) and f for f in formats):
        raise ValueError("Witness authorisation bundle_formats must be a list of strings")
    return {
        "protocol_version": B2_AUTHORIZATION_PROTOCOL_VERSION,
        "witness_key_id": key_id,
        "witness_mode": B2_WITNESS_MODE,
        "profiles": list(profiles),
        "bundle_formats": list(formats),
        "not_after": str(doc["not_after"]) if doc.get("not_after") else None,
    }


def to_verifier_authorization(doc: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Convert an authorisation document to ``hea_verifier`` input form."""
    valid = validate_witness_authorization(doc)
    return {valid["witness_key_id"]: {"profiles": list(valid["profiles"])}}


# -- role separation -----------------------------------------------------------


def _public_key_digest(public_key_pem: bytes) -> str:
    load_ed25519_public_key(public_key_pem)  # validates the key
    return sha256_bytes(public_key_pem)


def public_digest_of_private(private_key_pem: bytes) -> str:
    """SHA-256 digest of the public PEM belonging to a private key."""
    private_key = load_ed25519_private_key(private_key_pem)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(public_pem)


def check_role_separation(
    witness_public_pem: bytes,
    checkpoint_public_pem: bytes | None,
    producer_public_pem: bytes | None,
    witness_key_id: str = "",
    producer_key_id: str = "",
) -> None:
    """Enforce that witness / checkpoint-signer / producer keys differ.

    Raises ValueError when any two public-key digests coincide, or when
    the witness and producer key ids coincide. Key *ids* alone are not
    trusted (a DSSE keyid is an unauthenticated hint); the digests are
    compared.
    """
    witness_digest = _public_key_digest(witness_public_pem)
    if (
        checkpoint_public_pem is not None
        and _public_key_digest(checkpoint_public_pem) == witness_digest
    ):
        raise ValueError("Role separation violated: checkpoint-signer key equals the witness key")
    if (
        producer_public_pem is not None
        and _public_key_digest(producer_public_pem) == witness_digest
    ):
        raise ValueError(
            "Role separation violated: producer (receipt-signer) key equals "
            "the witness key — one key must not sign both roles"
        )
    if witness_key_id and producer_key_id and witness_key_id == producer_key_id:
        raise ValueError("Role separation violated: witness key_id equals producer key_id")


# -- re-executing witness ------------------------------------------------------


class B2ReexecutingWitness:
    """In-process core of the Model B2 witness.

    Wraps a :class:`WitnessService` configured with
    ``witness_mode="separate-machine"`` and adds the re-execution step:
    the witness runs the checks itself and only attests agreement.
    """

    def __init__(
        self,
        private_key_pem: bytes,
        key_id: str,
        log_id: str = "hea-b2-log-001",
        log_path: str | Path | None = None,
        checkpoint_private_key_pem: bytes | None = None,
        checkpoint_key_id: str = "",
        authorization: dict[str, Any] | None = None,
    ) -> None:
        check_private_key_not_test_only(private_key_pem)
        if checkpoint_private_key_pem is not None:
            check_private_key_not_test_only(checkpoint_private_key_pem)
            witness_pub = (
                load_ed25519_private_key(private_key_pem)
                .public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            checkpoint_pub = (
                load_ed25519_private_key(checkpoint_private_key_pem)
                .public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            check_role_separation(witness_pub, checkpoint_pub, None, key_id)
        self.key_id = key_id
        self.log_id = log_id
        self._log_path = Path(log_path) if log_path is not None else None
        # Kept for sign_completeness_statement: the execution completeness
        # statement is signed by the log-operator (checkpoint-signer) key,
        # never by the witness attestation key (role separation, §9.2).
        self._checkpoint_private_key_pem = (
            bytes(checkpoint_private_key_pem) if checkpoint_private_key_pem is not None else None
        )
        self._checkpoint_key_id = checkpoint_key_id
        self.authorization = (
            validate_witness_authorization(authorization) if authorization is not None else None
        )
        if self.authorization is not None and self.authorization["witness_key_id"] != key_id:
            raise ValueError(
                "Witness authorisation witness_key_id does not match this witness key_id"
            )
        self._service = WitnessService(
            private_key_pem,
            key_id=key_id,
            log_id=log_id,
            log_path=log_path,
            checkpoint_private_key_pem=checkpoint_private_key_pem,
            checkpoint_key_id=checkpoint_key_id,
            witness_mode=B2_WITNESS_MODE,
        )

    # -- observation: the witness receives the bytes and digests them itself
    def receive_bundle(self, package_bytes: bytes, profile_bytes: bytes) -> dict[str, str]:
        """Digest the bundle/profile bytes the witness received (not a producer claim)."""
        bundle_digest = self._service.observe_bytes("package", package_bytes)
        profile_digest = self._service.observe_bytes("profile", profile_bytes)
        return {"bundle_digest": bundle_digest, "profile_digest": profile_digest}

    def observe_file(self, path: str | Path) -> str:
        return self._service.observe_file(path)

    def code_digest(self) -> str:
        """Code digest of the witness's own ``oev`` install (§1.2 scope)."""
        return self._service.code_digest()

    # -- pre-binding / log / attestation: delegated to the Model A core -----
    def issue_commitment(
        self, partial_prebinding: dict[str, Any], issued_at_claimed: str
    ) -> dict[str, Any]:
        return self._service.issue_commitment(partial_prebinding, issued_at_claimed)

    def start_execution(
        self, execution_id: str, commitment_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._service.start_execution(execution_id, commitment_digest, claimed_time)

    def check_completed(
        self, execution_id: str, check_id: str, result_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._service.check_completed(execution_id, check_id, result_digest, claimed_time)

    def complete_execution(
        self, execution_id: str, status: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._service.complete_execution(execution_id, status, claimed_time)

    def attest(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._service.attest(payload)

    def checkpoint(self, claimed_time: str) -> dict[str, Any]:
        return self._service.checkpoint(claimed_time)

    def completeness(self, checkpoint: Any, claimed_time: str) -> dict[str, Any]:
        return self._service.completeness(checkpoint, claimed_time)

    def sign_completeness_statement(self, statement: Any) -> dict[str, Any]:
        """DSSE-sign an execution completeness statement.

        Signed with the checkpoint-signer (log operator) key, never the
        witness key. Raises ValueError when no checkpoint key was
        configured — an unsigned statement is never emitted silently.
        """
        if self._checkpoint_private_key_pem is None:
            raise ValueError(
                "No checkpoint-signer key configured; refusing to sign an "
                "execution completeness statement without the log-operator key"
            )
        return sign_execution_completeness(
            statement, self._checkpoint_private_key_pem, self._checkpoint_key_id
        )

    @property
    def events(self) -> list[Any]:
        return self._service.events

    @property
    def execution_id(self) -> str | None:
        return self._service.execution_id

    @property
    def commitment_digest(self) -> str | None:
        return self._service.commitment_digest

    def export_log_jsonl(self) -> bytes:
        return self._service.export_log_jsonl()

    # -- re-execution ----------------------------------------------------------
    def reexecute(
        self,
        package_bytes: bytes,
        profile: VerificationProfile,
        package_trust_keys: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run the checks *in the witness* and return its own results.

        Returns ``{"checks": [{check_id, status, detail}], "receipt_digest",
        "overall_result"}``. The witness receipt is the comparison basis
        only — it is not published as the execution receipt (the
        producer's receipt, bound to the attestations, is).
        """
        receipt, _envelope = execute_verification(
            package_bytes=package_bytes,
            profile=profile,
            package_trust_keys=package_trust_keys,
        )
        checks = [
            {
                "check_id": c.check_id,
                "status": str(c.status.value if isinstance(c.status, CheckStatus) else c.status),
                "detail": c.detail,
            }
            for c in receipt.checks
        ]
        return {
            "checks": checks,
            "receipt_digest": receipt.receipt_digest,
            "overall_result": str(
                receipt.overall_result.value
                if isinstance(receipt.overall_result, OverallResult)
                else receipt.overall_result
            ),
        }

    def compare_results(
        self,
        producer_checks: list[dict[str, Any]],
        witness_checks: list[dict[str, Any]],
    ) -> list[str]:
        """Compare producer-claimed vs witness-observed results.

        Compares ``status`` + ``detail`` per executed check;
        ``duration_ms`` is excluded (timing, not a result). Returns the
        list of mismatching check ids (empty = agreement).
        """
        witness_by_id = {c["check_id"]: c for c in witness_checks}
        mismatches: list[str] = []
        for claimed in producer_checks:
            check_id = str(claimed["check_id"])
            observed = witness_by_id.get(check_id)
            if observed is None:
                mismatches.append(check_id)
                continue
            if str(claimed.get("status")) != str(observed.get("status")) or str(
                claimed.get("detail", "")
            ) != str(observed.get("detail", "")):
                mismatches.append(check_id)
        return mismatches


def build_b2_attestation_payload(
    execution_id: str,
    commitment_digest: str,
    bundle_digest: str,
    profile_digest: str,
    code_version: dict[str, Any],
    check_id: str,
    result_status: str,
    result_detail: str,
    result_duration_ms: int,
    execution_status: str,
    log_anchor: dict[str, Any],
    claimed_time: str,
    witness_key_id: str,
    limitations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one per-check B2 attestation payload (unsigned; witness signs it)."""
    return build_attestation_payload(
        execution_id=execution_id,
        commitment_digest=commitment_digest,
        bundle_digest=bundle_digest,
        profile_digest=profile_digest,
        code_version=code_version,
        check_id=check_id,
        result_status=result_status,
        result_detail=result_detail,
        result_duration_ms=result_duration_ms,
        execution_status=execution_status,
        log_anchor=log_anchor,
        claimed_time=claimed_time,
        witness_key_id=witness_key_id,
        witness_software=B2_WITNESS_SOFTWARE,
        witness_mode=B2_WITNESS_MODE,
        limitations=limitations if limitations is not None else MODEL_B2_LIMITATIONS,
    )


# -- separate-process B2 witness client -----------------------------------------


class B2ProcessWitness:
    """Client for a B2 witness worker running as a separate process.

    Spawns ``python -m oev.b2_worker`` with an explicit interpreter
    (``python=`` — point it at the witness venv's interpreter for the
    two-venv prototype). The private key file is read by the worker
    process only and never crosses into this process.
    """

    channel = "stdio-pipe"

    def __init__(
        self,
        private_key_path: str | Path,
        key_id: str,
        log_path: str | Path,
        log_id: str = "hea-b2-log-001",
        timeout_seconds: float = 120.0,
        checkpoint_key_path: str | Path | None = None,
        checkpoint_key_id: str = "",
        authorization: dict[str, Any] | None = None,
        python: str | Path | None = None,
    ) -> None:
        self._private_key_path = Path(private_key_path)
        self.key_id = key_id
        self._log_path = Path(log_path)
        self._log_id = log_id
        self._timeout = timeout_seconds
        self._checkpoint_key_path = Path(checkpoint_key_path) if checkpoint_key_path else None
        self._checkpoint_key_id = checkpoint_key_id
        self.authorization = (
            validate_witness_authorization(authorization) if authorization is not None else None
        )
        if self.authorization is not None and self.authorization["witness_key_id"] != key_id:
            raise ValueError(
                "Witness authorisation witness_key_id does not match this witness key_id"
            )
        self._python = str(python) if python is not None else sys.executable
        self._proc: subprocess.Popen[str] | None = None

    @property
    def log_path(self) -> Path:
        return self._log_path

    def __enter__(self: _B2T) -> _B2T:  # noqa: PYI019 - Self needs typing_extensions on py3.10; TypeVar keeps the runtime dependency-free
        import os

        env = dict(os.environ)
        worker_argv = [
            self._python,
            "-m",
            "oev.b2_worker",
            "--key",
            str(self._private_key_path),
            "--key-id",
            self.key_id,
            "--log",
            str(self._log_path),
            "--log-id",
            self._log_id,
        ]
        if self._checkpoint_key_path is not None:
            worker_argv += [
                "--checkpoint-key",
                str(self._checkpoint_key_path),
                "--checkpoint-key-id",
                self._checkpoint_key_id,
            ]
        self._proc = subprocess.Popen(
            worker_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        ready = self._call("ping", {})
        if not ready.get("ok"):
            raise RuntimeError(f"B2 witness worker failed to start: {ready}")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._proc is not None:
            try:
                self._call("shutdown", {})
            except (RuntimeError, TimeoutError):
                pass
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _call(self, op: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("B2 witness worker is not running")
        request = json.dumps({"op": op, **payload})
        self._proc.stdin.write(request + "\n")
        self._proc.stdin.flush()
        import select

        ready, _w, _x = select.select([self._proc.stdout], [], [], self._timeout)
        if not ready:
            raise TimeoutError(
                f"B2 witness worker did not respond to {op!r} within {self._timeout}s"
            )
        line = self._proc.stdout.readline()
        if not line:
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"B2 witness worker closed stdout during {op!r}: {stderr[:500]}")
        response = json.loads(line)
        if not isinstance(response, dict) or not response.get("ok"):
            raise RuntimeError(
                f"B2 witness worker error for {op!r}: {response.get('error', response)}"
            )
        return response

    def receive_bundle(self, package_bytes: bytes, profile_bytes: bytes) -> dict[str, str]:
        result = self._call(
            "receive_bundle",
            {
                "package_b64": base64.b64encode(package_bytes).decode("ascii"),
                "profile_b64": base64.b64encode(profile_bytes).decode("ascii"),
            },
        )
        return {
            "bundle_digest": str(result["bundle_digest"]),
            "profile_digest": str(result["profile_digest"]),
        }

    def code_digest(self) -> str:
        return str(self._call("code_digest", {})["code_digest"])

    def issue_commitment(
        self, partial_prebinding: dict[str, Any], issued_at_claimed: str
    ) -> dict[str, Any]:
        return self._call(
            "commit", {"prebinding": partial_prebinding, "issued_at_claimed": issued_at_claimed}
        )

    def start_execution(
        self, execution_id: str, commitment_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._call(
            "start",
            {
                "execution_id": execution_id,
                "commitment_digest": commitment_digest,
                "claimed_time": claimed_time,
            },
        )

    def check_completed(
        self, execution_id: str, check_id: str, result_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._call(
            "check_completed",
            {
                "execution_id": execution_id,
                "check_id": check_id,
                "result_digest": result_digest,
                "claimed_time": claimed_time,
            },
        )

    def complete_execution(
        self, execution_id: str, status: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._call(
            "complete",
            {"execution_id": execution_id, "status": status, "claimed_time": claimed_time},
        )

    def attest(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call("attest", {"payload": payload})

    def checkpoint(self, claimed_time: str) -> dict[str, Any]:
        return self._call("checkpoint", {"claimed_time": claimed_time})

    def completeness(self, checkpoint: dict[str, Any], claimed_time: str) -> dict[str, Any]:
        return self._call("completeness", {"checkpoint": checkpoint, "claimed_time": claimed_time})

    def sign_completeness(self, statement: dict[str, Any]) -> dict[str, Any]:
        return self._call("sign_completeness", {"statement": statement})

    def reexecute(
        self,
        package_bytes: bytes,
        profile: VerificationProfile,
        package_trust_keys: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return self._call(
            "reexecute",
            {
                "package_b64": base64.b64encode(package_bytes).decode("ascii"),
                "profile": profile.to_dict(),
                "package_trust_keys": package_trust_keys or [],
            },
        )

    def compare_results(
        self,
        producer_checks: list[dict[str, Any]],
        witness_checks: list[dict[str, Any]],
    ) -> list[str]:
        witness_by_id = {c["check_id"]: c for c in witness_checks}
        mismatches: list[str] = []
        for claimed in producer_checks:
            check_id = str(claimed["check_id"])
            observed = witness_by_id.get(check_id)
            if observed is None:
                mismatches.append(check_id)
                continue
            if str(claimed.get("status")) != str(observed.get("status")) or str(
                claimed.get("detail", "")
            ) != str(observed.get("detail", "")):
                mismatches.append(check_id)
        return mismatches

    def export_log_jsonl(self) -> bytes:
        return self._log_path.read_bytes() if self._log_path.is_file() else b""


# -- two-party B2 run --------------------------------------------------------------


def run_b2_witnessed_verification(
    package_path: str | Path,
    profile_path: str | Path,
    witness: B2ReexecutingWitness | B2ProcessWitness,
    out_dir: str | Path,
    package_trust_keys: list[dict[str, Any]] | None = None,
    receipt_signing_key_pem: bytes | None = None,
    receipt_signer_key_id: str = "",
    receipt_signer_public_pem: bytes | None = None,
    witness_public_pem: bytes | None = None,
    adapter_label: str = "oept 0.1.3",
    tsa: Any | None = None,
    tsa_gen_time: str | None = None,
    producer_workdir: str | Path | None = None,
    witness_workdir: str | Path | None = None,
    signed_authorization: dict[str, Any] | None = None,
    authorization_issuer_trust_store: Any | None = None,
    require_signed_authorization: bool = False,
) -> dict[str, Any]:
    """Run a Model B2 witnessed verification (producer + re-executing witness).

    Flow: producer executes → witness receives the bytes, re-executes,
    compares → witness attests only on agreement → receipt finalised
    with the attestation binding. Any disagreement raises ValueError
    BEFORE any attestation is signed (fail-closed).

    ``tsa`` (optional) is a :class:`oev.tsa.MockTSA`: when given, every
    attestation digest is timestamped and the token is stored as a
    sidecar (``timestamp-tokens/<check_id>.dsse.json``); the attestation
    itself is unchanged (the oev-attestation/0.1 schema forbids extra
    fields). Without a TSA the manifest records
    ``timestamp_status: "UNVERIFIED"``.

    Round 4 additions: the run emits a signed log-completeness
    statement (``log-completeness.dsse.json``) and a signed execution
    completeness statement (``b2-completeness.dsse.json`` — executed /
    NOT_RUN / skipped per check, bound to the checkpoint + code
    digest); the attested ``code_version`` carries the policy digest
    (the profile digest) and the environment record, and the full
    code-digest document is recorded in the manifest. When
    ``signed_authorization`` is supplied its signature is verified
    against ``authorization_issuer_trust_store``; when
    ``require_signed_authorization`` is set an unsigned authorisation
    is refused outright.
    """
    from oev.tsa import MockTSA

    package_path = Path(package_path)
    profile_path = Path(profile_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    attest_dir = out_dir / "attestations"
    attest_dir.mkdir(parents=True, exist_ok=True)

    package_bytes = package_path.read_bytes()
    if len(package_bytes) > 512 * 1024 * 1024:
        raise ValueError("Package exceeds the 512 MiB bound")
    profile = load_profile(profile_path)
    profile_bytes = canonicalize_json(profile.to_dict())
    claimed_time = utc_now_iso()

    # Role separation (code-enforced, §9.2): the producer's receipt key
    # must differ from the witness key. The witness↔checkpoint split is
    # enforced in B2ReexecutingWitness / the worker at construction.
    if receipt_signing_key_pem is not None:
        producer_pub = (
            load_ed25519_private_key(receipt_signing_key_pem)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    elif receipt_signer_public_pem is not None:
        producer_pub = bytes(receipt_signer_public_pem)
    else:
        producer_pub = None
    if producer_pub is not None and witness_public_pem is not None:
        # Digest-level check (key ids alone are untrusted hints).
        check_role_separation(
            bytes(witness_public_pem),
            None,
            producer_pub,
            witness_key_id=witness.key_id,
            producer_key_id=receipt_signer_key_id,
        )
    elif receipt_signer_key_id and receipt_signer_key_id == witness.key_id:
        raise ValueError("Role separation violated: receipt-signer key_id equals witness key_id")

    # 1. Witness receives the bytes itself; producer cross-checks digests.
    received = witness.receive_bundle(package_bytes, profile_bytes)
    witness_bundle_digest = str(received["bundle_digest"])
    witness_profile_digest = str(received["profile_digest"])
    local_bundle_digest = sha256_bytes(package_bytes)
    local_profile_digest = compute_profile_digest(profile)
    if witness_bundle_digest != local_bundle_digest:
        raise ValueError("Witness bundle digest disagrees with producer digest")
    if witness_profile_digest != local_profile_digest:
        raise ValueError("Witness profile digest disagrees with producer digest")
    witness_code_digest = witness.code_digest()
    producer_code_digest = compute_code_digest()
    if witness_code_digest != producer_code_digest:
        raise ValueError(
            "Code digest mismatch: witness code digest != producer code digest "
            "(witness and producer must run the same code version)"
        )
    # Round 4: bind code / policy / dependency digests to the commitment.
    # ``policy_digest`` is the profile digest (the policy the code ran
    # under); ``environment`` records interpreter + venv fingerprint.
    # The full code-digest document (oev-code-digest/0.1) is recorded
    # in the manifest so a verifier can compare it field by field.
    code_digest_document = build_code_digest_document(
        f"oev {_OEV_VERSION}",
        adapter_label,
        policy_digest=local_profile_digest,
    )
    code_version = {
        "engine": f"oev {_OEV_VERSION}",
        "adapter": adapter_label,
        "code_digest": witness_code_digest,
        "policy_digest": local_profile_digest,
        "environment": build_environment_record(),
    }

    # Authorisation: the witness may only attest its authorised profiles/formats.
    # Round 4: a signed authorisation (DSSE, issuer-signed) takes precedence
    # over the unsigned in-process document; when signed authorisation is
    # required, an unsigned document is refused outright.
    witness_channel = str(getattr(witness, "channel", "stdio-pipe") or "stdio-pipe")
    signed_auth_doc: Any = None
    if signed_authorization is not None:
        expected_wit_digest = None
        if witness_public_pem is not None:
            expected_wit_digest = sha256_bytes(bytes(witness_public_pem))
        signed_auth_doc, auth_ok, auth_note = verify_signed_witness_authorization(
            signed_authorization,
            authorization_issuer_trust_store,
            expected_witness_public_key_digest=expected_wit_digest,
        )
        if not auth_ok or signed_auth_doc is None:
            raise ValueError(f"Signed witness authorisation rejected: {auth_note}")
        if signed_auth_doc.witness_key_id != witness.key_id:
            raise ValueError(
                "Signed witness authorisation is for a different witness key_id "
                f"({signed_auth_doc.witness_key_id!r} != {witness.key_id!r})"
            )
        if profile.profile_id not in signed_auth_doc.authorized_profiles:
            raise ValueError(f"Witness is not authorised for profile {profile.profile_id!r}")
    elif require_signed_authorization:
        raise ValueError(
            "Unsigned witness authorisation rejected: this B2 deployment "
            "requires a signed (issuer-signed DSSE) authorisation document"
        )
    authorization = getattr(witness, "authorization", None)
    if signed_auth_doc is None and authorization is not None:
        if profile.profile_id not in authorization["profiles"]:
            raise ValueError(f"Witness is not authorised for profile {profile.profile_id!r}")
        if (
            authorization["bundle_formats"]
            and profile.target_format not in authorization["bundle_formats"]
        ):
            raise ValueError(
                f"Witness is not authorised for bundle format {profile.target_format!r}"
            )

    check_ids = list(dict.fromkeys(profile.required_checks + profile.optional_checks))
    trust_inputs_digest = compute_trust_inputs_digest(
        [
            {
                "trust_id": str(k.get("key_id", "")),
                "type": "public_key",
                "digest": sha256_bytes(
                    k["public_key_pem"].encode("utf-8")
                    if isinstance(k.get("public_key_pem"), str)
                    else bytes(k.get("public_key_pem", b""))
                ),
            }
            for k in (package_trust_keys or [])
        ]
    )
    partial_prebinding = build_prebinding(
        bundle_digest=witness_bundle_digest,
        bundle_format=profile.target_format,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_digest=witness_profile_digest,
        code_version=code_version,
        check_ids=check_ids,
        input_digests={
            "package": witness_bundle_digest,
            "profile": witness_profile_digest,
        },
        trust_inputs_digest=trust_inputs_digest,
        nonce=None,  # witness-generated; any producer nonce is discarded
        witness_mode=B2_WITNESS_MODE,
        witness_key_id=witness.key_id,
    )

    # 2. Commitment (witness fills the nonce, derives the Execution ID).
    commitment_result = witness.issue_commitment(partial_prebinding, claimed_time)
    execution_id = str(commitment_result["execution_id"])
    prebinding = dict(commitment_result["prebinding"])
    commitment_envelope = dict(commitment_result["commitment_envelope"])
    commitment_digest = str(commitment_result["commitment_digest"])

    # 3. Producer executes; witness re-executes independently.
    witness.start_execution(execution_id, commitment_digest, claimed_time)
    producer_receipt, _producer_envelope = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
        package_trust_keys=package_trust_keys,
    )
    witness_result = witness.reexecute(package_bytes, profile, package_trust_keys)
    producer_checks = [
        {
            "check_id": c.check_id,
            "status": str(c.status.value if isinstance(c.status, CheckStatus) else c.status),
            "detail": c.detail,
        }
        for c in producer_receipt.checks
    ]
    mismatches = witness.compare_results(producer_checks, list(witness_result["checks"]))
    if mismatches:
        raise ValueError(
            "B2 witness re-execution disagrees with the producer claim for checks "
            f"{mismatches}; attestation refused (fail-closed, no attestation signed)"
        )
    execution_status = (
        "INTERRUPTED"
        if producer_receipt.overall_result == OverallResult.EXECUTION_INCOMPLETE
        else "COMPLETED"
    )
    completion_status = (
        "FAILED"
        if producer_receipt.overall_result == OverallResult.EXECUTION_INCOMPLETE
        else "COMPLETED"
    )

    # 4. Per-check log + attestation (NOT_RUN checks: no event, no attestation).
    attestation_envelopes: dict[str, dict[str, Any]] = {}
    attestation_digests: dict[str, str] = {}
    log_anchors: dict[str, dict[str, Any]] = {}
    for check in producer_receipt.checks:
        status = str(check.status.value if isinstance(check.status, CheckStatus) else check.status)
        if status not in CHECK_STATUS_EXECUTED:
            continue
        result_digest = sha256_bytes(canonicalize_json(check.to_dict()))
        completed = witness.check_completed(
            execution_id, check.check_id, result_digest, claimed_time
        )
        event = dict(completed["event"])
        anchor = {
            "log_id": event["log_id"],
            "leaf_index": int(event["seq"]),
            "leaf_hash": str(completed["leaf_hash"]),
        }
        log_anchors[check.check_id] = anchor
        payload = build_b2_attestation_payload(
            execution_id=execution_id,
            commitment_digest=commitment_digest,
            bundle_digest=witness_bundle_digest,
            profile_digest=witness_profile_digest,
            code_version=code_version,
            check_id=check.check_id,
            result_status=status,
            result_detail=check.detail,
            result_duration_ms=check.duration_ms,
            execution_status=execution_status,
            log_anchor=anchor,
            claimed_time=claimed_time,
            witness_key_id=witness.key_id,
            limitations=limitations_for_channel(witness_channel),
        )
        envelope = witness.attest(payload)
        attestation_envelopes[check.check_id] = (
            dict(envelope["envelope"]) if "envelope" in envelope else dict(envelope)
        )
        attestation_digests[check.check_id] = compute_attestation_digest(payload)

    witness.complete_execution(execution_id, completion_status, claimed_time)

    # 5. Checkpoint + inclusion proofs.
    checkpoint_result = witness.checkpoint(claimed_time)
    checkpoint_envelope = dict(checkpoint_result["envelope"])
    checkpoint = dict(checkpoint_result["checkpoint"])
    checkpoint_digest = LogCheckpoint.from_dict(checkpoint).checkpoint_digest()

    # 5b. Signed completeness (round 4): the log operator's completeness
    # statement (DISPROVEN condition 3) and the B2 execution
    # completeness statement (executed / NOT_RUN / skipped per check,
    # bound to checkpoint + code digest). Either may be absent when the
    # witness was configured without a checkpoint key — that is
    # recorded honestly in the manifest instead of failing the run.
    log_completeness_envelope: dict[str, Any] | None = None
    log_completeness_note = ""
    try:
        if isinstance(witness, B2ReexecutingWitness):
            comp_result = witness.completeness(LogCheckpoint.from_dict(checkpoint), claimed_time)
        else:
            comp_result = witness.completeness(checkpoint, claimed_time)
        log_completeness_envelope = dict(comp_result["envelope"])
        (out_dir / "log-completeness.dsse.json").write_bytes(
            canonicalize_json(log_completeness_envelope)
        )
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        log_completeness_note = f"log completeness statement not emitted: {exc}"
    execution_completeness_envelope: dict[str, Any] | None = None
    execution_completeness_statement: dict[str, Any] | None = None
    execution_completeness_note = ""
    try:
        statement = build_execution_completeness(
            execution_id=execution_id,
            checkpoint_digest=checkpoint_digest,
            code_digest=witness_code_digest,
            witness_key_id=witness.key_id,
            receipt_checks=[
                {
                    "check_id": c.check_id,
                    "status": str(
                        c.status.value if isinstance(c.status, CheckStatus) else c.status
                    ),
                }
                for c in producer_receipt.checks
            ],
            profile_check_ids=check_ids,
            claimed_time=claimed_time,
            policy_digest=local_profile_digest,
        )
        execution_completeness_statement = statement.to_dict()
        if isinstance(witness, B2ReexecutingWitness):
            execution_completeness_envelope = witness.sign_completeness_statement(statement)
        elif hasattr(witness, "sign_completeness"):
            signed = witness.sign_completeness(statement.to_dict())
            execution_completeness_envelope = (
                dict(signed["envelope"]) if "envelope" in signed else dict(signed)
            )
        else:
            execution_completeness_note = (
                "execution completeness statement built but not signed: "
                "witness does not support sign_completeness"
            )
            execution_completeness_envelope = None
        if execution_completeness_envelope is not None:
            (out_dir / "b2-completeness.dsse.json").write_bytes(
                canonicalize_json(execution_completeness_envelope)
            )
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        execution_completeness_note = f"execution completeness statement not emitted: {exc}"
        execution_completeness_envelope = None
        execution_completeness_statement = None

    if isinstance(witness, B2ReexecutingWitness) or hasattr(witness, "export_log_jsonl"):
        log_bytes = witness.export_log_jsonl()
    else:
        log_path = getattr(witness, "log_path", None)
        log_bytes = Path(str(log_path)).read_bytes() if log_path else b""
    log_events = events_from_jsonl(log_bytes)
    leaves = [e.leaf_hash() for e in log_events]
    inclusion_proofs = {
        check_id: merkle_inclusion_proof(leaves, int(anchor["leaf_index"]))
        for check_id, anchor in log_anchors.items()
    }

    # 6. Optional TSA timestamping (sidecar; attestation schema is unchanged).
    timestamp_tokens: dict[str, dict[str, Any]] = {}
    timestamp_status = "UNVERIFIED"
    if tsa is not None:
        if not isinstance(tsa, MockTSA):
            raise ValueError("Only MockTSA is supported offline; no real TSA is contacted")
        token_dir = out_dir / "timestamp-tokens"
        token_dir.mkdir(parents=True, exist_ok=True)
        for check_id, digest in sorted(attestation_digests.items()):
            stamped = tsa.timestamp(digest, gen_time=tsa_gen_time)
            timestamp_tokens[check_id] = dict(stamped["token"])
            (token_dir / f"{check_id}.dsse.json").write_bytes(
                canonicalize_json(dict(stamped["envelope"]))
            )
        timestamp_status = "TSA_VERIFIED (mock-tsa/0.1 — NOT production trusted time)"

    # 7. Receipt finalised WITH the attestation binding (§5.2 rule 2).
    receipt_dict = producer_receipt.to_dict(include_digest=False)
    receipt_dict["execution_attestations"] = [
        {"check_id": check_id, "attestation_digest": digest}
        for check_id, digest in sorted(attestation_digests.items())
    ]
    final_receipt = finalize_receipt(receipt_dict)
    receipt_envelope: dict[str, Any] | None = None
    if receipt_signing_key_pem is not None:
        from .signing import sign_receipt_dsse

        receipt_envelope = sign_receipt_dsse(
            receipt=final_receipt,
            private_key_pem=receipt_signing_key_pem,
            key_id=receipt_signer_key_id,
        )

    # 8. Write artifacts.
    receipt_path = out_dir / "receipt.json"
    if receipt_envelope is not None:
        receipt_path.write_bytes(canonicalize_json(receipt_envelope))
    else:
        receipt_path.write_bytes(canonicalize_json(final_receipt.to_dict(include_digest=True)))
    for check_id, envelope in attestation_envelopes.items():
        (attest_dir / f"{check_id}.dsse.json").write_bytes(canonicalize_json(envelope))
    (out_dir / "execution-log.jsonl").write_bytes(log_bytes)
    (out_dir / "checkpoint.dsse.json").write_bytes(canonicalize_json(checkpoint_envelope))
    (out_dir / "commitment.dsse.json").write_bytes(canonicalize_json(commitment_envelope))
    (out_dir / "prebinding.json").write_bytes(canonicalize_json(prebinding))
    manifest = {
        "protocol_version": "oev-attestation/0.1",
        "execution_id": execution_id,
        "commitment_digest": commitment_digest,
        "receipt_digest": final_receipt.receipt_digest,
        "overall_result": str(
            final_receipt.overall_result.value
            if isinstance(final_receipt.overall_result, OverallResult)
            else final_receipt.overall_result
        ),
        "witness_mode": B2_WITNESS_MODE,
        "witness_key_id": witness.key_id,
        "witness_software": B2_WITNESS_SOFTWARE,
        "code_digest": code_version["code_digest"],
        "witness_code_digest": witness_code_digest,
        "producer_code_digest": producer_code_digest,
        "reexecution": "witness re-executed all checks; attested only on agreement",
        "timestamp_status": timestamp_status,
        "isolation_claim": "prototype-process-venv-key-workdir-only",
        "channel": witness_channel,
        "code_digest_document": code_digest_document,
        "log_completeness": {
            "emitted": log_completeness_envelope is not None,
            "note": log_completeness_note,
        },
        "execution_completeness": {
            "emitted": execution_completeness_envelope is not None,
            "note": execution_completeness_note,
            "statement": execution_completeness_statement,
        },
        "signed_authorization": {
            "required": require_signed_authorization,
            "present": signed_authorization is not None,
            "issuer_key_id": (
                str(signed_auth_doc.issuer_key_id) if signed_auth_doc is not None else None
            ),
        },
        "isolation": {
            "producer_workdir": str(producer_workdir) if producer_workdir else None,
            "witness_workdir": str(witness_workdir) if witness_workdir else None,
            "separate_process": True,
            "separate_keys": True,
            "separate_workdir": bool(producer_workdir and witness_workdir),
            "channel": witness_channel,
            "mutual_tls": witness_channel.startswith("mtls"),
            "physical_or_administrative_independence": False,
        },
        "checkpoint": checkpoint,
        "inclusion_proofs": inclusion_proofs,
        "attestation_digests": attestation_digests,
        "timestamp_tokens": timestamp_tokens,
        "notes": [
            "Time is NOT proven: claimed_time fields are self-asserted; ordering comes from log sequence only.",
            "Model B2 witness: separate process, re-executing; no protection against witness compromise or common-mode code faults.",
            "Prototype isolation only: NO physical/administrative independence claimed.",
        ],
    }
    (out_dir / "b2-manifest.json").write_bytes(canonicalize_json(manifest))

    return {
        "execution_id": execution_id,
        "commitment_digest": commitment_digest,
        "receipt_digest": final_receipt.receipt_digest,
        "overall_result": manifest["overall_result"],
        "witness_mode": B2_WITNESS_MODE,
        "witness_key_id": witness.key_id,
        "witness_code_digest": witness_code_digest,
        "producer_code_digest": producer_code_digest,
        "attested_checks": sorted(attestation_digests),
        "timestamp_status": timestamp_status,
        "channel": witness_channel,
        "log_completeness_path": (
            str(out_dir / "log-completeness.dsse.json")
            if log_completeness_envelope is not None
            else None
        ),
        "execution_completeness_path": (
            str(out_dir / "b2-completeness.dsse.json")
            if execution_completeness_envelope is not None
            else None
        ),
        "code_digest_document": code_digest_document,
        "out_dir": str(out_dir),
        "receipt_path": str(receipt_path),
        "manifest_path": str(out_dir / "b2-manifest.json"),
    }


__all__ = [
    "B2_AUTHORIZATION_PROTOCOL_VERSION",
    "B2_WITNESS_MODE",
    "B2_WITNESS_SOFTWARE",
    "MODEL_B2_LIMITATIONS",
    "B2ProcessWitness",
    "B2ReexecutingWitness",
    "build_b2_attestation_payload",
    "check_role_separation",
    "limitations_for_channel",
    "public_digest_of_private",
    "run_b2_witnessed_verification",
    "to_verifier_authorization",
    "validate_witness_authorization",
]

# SPDX-License-Identifier: Apache-2.0

"""Local-process execution witness — Model A (HEA design §2.2).

The witness is a *separate process* from the producer: it holds its
Ed25519 private key, issues commitments with fresh nonces, computes input
digests itself from files it reads, appends to the execution log, and
signs per-check attestations. The producer never sees the private key.

Honest labelling (§2.2, rejected alternative R6): a Model A attestation
is "observed by a software witness running as a separate process on the
same machine". It is NEVER presented as hardware-backed, independent, or
tamper-proof evidence. It protects against an honest-but-faulty producer
(wrong results, skipped steps, missing log entries are caught by the
witness's own digest and log checks); it does NOT protect against a
malicious producer on the same machine, a compromised machine, or a
dishonest witness operator. Every attestation carries this limit in its
``limitations`` (``WITNESS_LOCAL_ONLY``).

Two entry points share the same core (``WitnessService``):
- in-process use (tests, embedding): instantiate ``WitnessService`` directly;
- separate-process use (production): ``LocalProcessWitness`` spawns
  ``python -m oev.witness_worker`` and speaks the JSON-lines protocol.
  The worker process is the only holder of the private key.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, TypeVar

_WitnessT = TypeVar("_WitnessT", bound="LocalProcessWitness")

from cryptography.hazmat.primitives import serialization

from .attestation import (
    KNOWN_TEST_KEY_DIGESTS,
    compute_attestation_id,
    sign_attestation_dsse,
    validate_attestation_payload,
)
from .canonical import canonicalize_json
from .execution import (
    build_commitment_envelope,
    build_prebinding,
    compute_code_digest,
    compute_execution_id,
    generate_nonce,
    is_valid_execution_id,
)
from .execution_log import (
    GENESIS_PREV_HASH,
    LogCheckpoint,
    LogEvent,
    build_checkpoint,
    events_from_jsonl,
    events_to_jsonl,
    sign_checkpoint_dsse,
    sign_completeness_dsse,
)
from .hashing import sha256_bytes
from .signing import load_ed25519_private_key

WITNESS_SOFTWARE = "oev-witness 0.1.0"
MODEL_A_LIMITATIONS: list[dict[str, Any]] = [
    {
        "code": "WITNESS_LOCAL_ONLY",
        "description": (
            "Local software witness (separate process, same machine). "
            "No protection against machine compromise or a malicious producer "
            "on the same machine. Time is claimed, not proven."
        ),
        "material": True,
    },
    {
        "code": "TIME_NOT_PROVEN",
        "description": "claimed_time is self-asserted; ordering comes from log sequence only.",
        "material": True,
    },
]


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_private_key_not_test_only(private_key_pem: bytes) -> None:
    """Refuse the committed OEPT test-only key as a witness key (design §9.1)."""
    private_key = load_ed25519_private_key(private_key_pem)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sha256_bytes(public_pem) in KNOWN_TEST_KEY_DIGESTS:
        raise ValueError("Refusing the committed test-only key as a witness key")


class WitnessService:
    """In-process core of the Model A witness. State lives in memory + log file."""

    def __init__(
        self,
        private_key_pem: bytes,
        key_id: str,
        log_id: str = "hea-log-001",
        log_path: str | Path | None = None,
        witness_software: str = WITNESS_SOFTWARE,
        checkpoint_private_key_pem: bytes | None = None,
        checkpoint_key_id: str = "",
        witness_mode: str = "local-process",
    ) -> None:
        check_private_key_not_test_only(private_key_pem)
        if witness_mode not in ("local-process", "separate-machine", "tee"):
            raise ValueError(f"Unknown witness_mode: {witness_mode!r}")
        self.witness_mode = witness_mode
        self._private_key_pem = bytes(private_key_pem)
        self.key_id = key_id
        # Role separation (§9.2): checkpoints are signed with a distinct
        # checkpoint-signer key, never with the witness key. A missing
        # checkpoint key fails closed at checkpoint time.
        if checkpoint_private_key_pem is not None:
            check_private_key_not_test_only(checkpoint_private_key_pem)
        self._checkpoint_private_key_pem = (
            bytes(checkpoint_private_key_pem) if checkpoint_private_key_pem is not None else None
        )
        self._checkpoint_key_id = checkpoint_key_id
        self.log_id = log_id
        self.witness_software = witness_software
        self._events: list[LogEvent] = []
        self._log_path = Path(log_path) if log_path is not None else None
        self._execution_id: str | None = None
        self._commitment_digest: str | None = None
        self._observed_digests: dict[str, str] = {}
        if self._log_path is not None and self._log_path.is_file():
            self._events = events_from_jsonl(self._log_path.read_bytes())
        self._prev_checkpoint_digest = GENESIS_PREV_HASH

    # -- observation -------------------------------------------------------
    def observe_file(self, path: str | Path) -> str:
        """Compute the SHA-256 digest of a file the witness reads itself."""
        target = Path(path)
        data = target.read_bytes()
        if len(data) > 512 * 1024 * 1024:
            raise ValueError(f"Observed file exceeds the 512 MiB bound: {target}")
        digest = sha256_bytes(data)
        self._observed_digests[target.name] = digest
        return digest

    def observe_bytes(self, name: str, data: bytes) -> str:
        """Digest bytes received over the producer channel.

        Weaker than observe_file: the bytes arrived through the producer,
        so a malicious producer could send different bytes than it executed
        on. Recorded as a limitation by callers that use it.
        """
        digest = sha256_bytes(data)
        self._observed_digests[name] = digest
        return digest

    def code_digest(self) -> str:
        """Code digest of the witness's own ``oev`` install (§1.2 scope)."""
        return compute_code_digest()

    # -- pre-binding ---------------------------------------------------------
    def issue_commitment(
        self, partial_prebinding: dict[str, Any], issued_at_claimed: str
    ) -> dict[str, Any]:
        """Fill the nonce, derive the Execution ID, sign the commitment.

        The producer supplies the pre-binding *without* a nonce; the nonce
        is witness-generated so a producer cannot pre-pick execution ids.
        """
        prebinding = dict(partial_prebinding)
        prebinding["nonce"] = generate_nonce()
        prebinding.setdefault("execution_context", {})
        prebinding["execution_context"] = {
            "witness_mode": self.witness_mode,
            "witness_key_id": self.key_id,
        }
        execution_id = compute_execution_id(prebinding)
        envelope = build_commitment_envelope(
            prebinding, execution_id, issued_at_claimed, self._private_key_pem, self.key_id
        )
        self._execution_id = execution_id
        self._commitment_digest = sha256_bytes(
            canonicalize_json(
                {
                    "protocol_version": prebinding["protocol_version"],
                    "execution_id": execution_id,
                    "nonce": prebinding["nonce"],
                    "bundle_digest": prebinding["bundle_digest"],
                    "profile_digest": prebinding["profile_digest"],
                    "code_version": prebinding["code_version"],
                    "check_ids": prebinding["check_ids"],
                    "input_digests": prebinding["input_digests"],
                    "issued_at_claimed": issued_at_claimed,
                }
            )
        )
        return {
            "execution_id": execution_id,
            "prebinding": prebinding,
            "commitment_envelope": envelope,
            "commitment_digest": self._commitment_digest,
        }

    # -- log -----------------------------------------------------------------
    def _append_event(
        self,
        event_type: str,
        execution_id: str,
        event_digest: str,
        claimed_time: str,
        check_id: str | None = None,
    ) -> LogEvent:
        prev_hash = self._events[-1].leaf_hash() if self._events else GENESIS_PREV_HASH
        event = LogEvent(
            log_id=self.log_id,
            seq=len(self._events),
            event_type=event_type,
            execution_id=execution_id,
            check_id=check_id,
            event_digest=event_digest,
            prev_hash=prev_hash,
            claimed_time=claimed_time,
        )
        self._events.append(event)
        if self._log_path is not None:
            with self._log_path.open("ab") as handle:
                handle.write(canonicalize_json(event.to_dict()) + b"\n")
        return event

    def start_execution(
        self, execution_id: str, commitment_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        if self._execution_id is not None and execution_id != self._execution_id:
            raise ValueError("start_execution for an execution_id this witness did not commit")
        if self._commitment_digest is not None and commitment_digest != self._commitment_digest:
            raise ValueError(
                "start_execution commitment digest does not match the issued commitment"
            )
        event = self._append_event(
            "EXECUTION_STARTED",
            execution_id,
            sha256_bytes(canonicalize_json({"commitment_digest": commitment_digest})),
            claimed_time,
        )
        return {"event": event.to_dict(), "leaf_hash": event.leaf_hash()}

    def check_completed(
        self, execution_id: str, check_id: str, result_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        event = self._append_event(
            "CHECK_COMPLETED",
            execution_id,
            result_digest,
            claimed_time,
            check_id=check_id,
        )
        return {"event": event.to_dict(), "leaf_hash": event.leaf_hash()}

    def complete_execution(
        self, execution_id: str, status: str, claimed_time: str
    ) -> dict[str, Any]:
        if status not in ("COMPLETED", "FAILED"):
            raise ValueError(f"Unknown completion status: {status!r}")
        event_type = "EXECUTION_COMPLETED" if status == "COMPLETED" else "EXECUTION_FAILED"
        event = self._append_event(
            event_type,
            execution_id,
            sha256_bytes(canonicalize_json({"status": status})),
            claimed_time,
        )
        return {"event": event.to_dict(), "leaf_hash": event.leaf_hash()}

    # -- attestation ---------------------------------------------------------
    def attest(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate and sign an attestation payload (DSSE envelope out).

        The witness cross-checks, against its own log and commitment:
        execution_id / commitment digest / bundle+profile digests /
        log_anchor leaf. A payload that fails any cross-check is refused —
        the witness does not blindly sign producer claims (rejected R1).
        """
        validate_attestation_payload(payload)
        execution_id = str(payload["execution_id"])
        if self._execution_id is not None and execution_id != self._execution_id:
            raise ValueError("attest: execution_id does not match the issued commitment")
        if (
            self._commitment_digest is not None
            and str(payload.get("execution_commitment_digest")) != self._commitment_digest
        ):
            raise ValueError("attest: commitment digest does not match the issued commitment")
        anchor = dict(payload.get("log_anchor", {}))
        leaf_index = int(anchor.get("leaf_index", -1))
        if leaf_index < 0 or leaf_index >= len(self._events):
            raise ValueError("attest: log_anchor leaf_index is out of range for the witness log")
        event = self._events[leaf_index]
        if event.leaf_hash() != str(anchor.get("leaf_hash", "")):
            raise ValueError("attest: log_anchor leaf_hash does not match the witness log")
        if event.execution_id != execution_id or event.check_id != str(payload["check_id"]):
            raise ValueError("attest: log_anchor does not describe this check's completion")
        if event.event_type != "CHECK_COMPLETED":
            raise ValueError("attest: log_anchor is not a CHECK_COMPLETED event")
        if str(payload["witness"]["witness_key_id"]) != self.key_id:
            raise ValueError("attest: witness_key_id is not this witness")
        return sign_attestation_dsse(payload, self._private_key_pem, self.key_id)

    def checkpoint(self, claimed_time: str) -> dict[str, Any]:
        if self._checkpoint_private_key_pem is None:
            raise ValueError(
                "No checkpoint-signer key configured; refusing to sign a checkpoint "
                "with the witness key (role separation, §9.2)"
            )
        checkpoint = build_checkpoint(
            self._events, self.log_id, claimed_time, self._prev_checkpoint_digest
        )
        envelope = sign_checkpoint_dsse(
            checkpoint, self._checkpoint_private_key_pem, self._checkpoint_key_id
        )
        self._prev_checkpoint_digest = checkpoint.checkpoint_digest()
        return {"checkpoint": checkpoint.to_dict(), "envelope": envelope}

    def completeness(self, checkpoint: LogCheckpoint, claimed_time: str) -> dict[str, Any]:
        from .execution_log import LogCompleteness

        if self._checkpoint_private_key_pem is None:
            raise ValueError("No checkpoint-signer (log operator) key configured")
        statement = LogCompleteness(
            log_id=self.log_id,
            through_seq=checkpoint.checkpoint_seq,
            checkpoint_digest=checkpoint.checkpoint_digest(),
            claimed_time=claimed_time,
        )
        envelope = sign_completeness_dsse(
            statement, self._checkpoint_private_key_pem, self._checkpoint_key_id
        )
        return {"statement": statement.to_dict(), "envelope": envelope}

    # -- accessors -----------------------------------------------------------
    @property
    def events(self) -> list[LogEvent]:
        return list(self._events)

    @property
    def execution_id(self) -> str | None:
        return self._execution_id

    @property
    def commitment_digest(self) -> str | None:
        return self._commitment_digest

    def export_log_jsonl(self) -> bytes:
        return events_to_jsonl(self._events)


def build_attestation_payload(
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
    witness_software: str = WITNESS_SOFTWARE,
    witness_mode: str = "local-process",
    limitations: list[dict[str, Any]] | None = None,
    receipt_digest: str | None = None,
) -> dict[str, Any]:
    """Build one per-check attestation payload (unsigned; the witness signs it)."""
    inputs_digest = sha256_bytes(
        canonicalize_json(
            {"bundle_digest": bundle_digest, "profile_digest": profile_digest, "check_id": check_id}
        )
    )
    payload: dict[str, Any] = {
        "protocol_version": "oev-attestation/0.1",
        "attestation_id": compute_attestation_id(execution_id, check_id),
        "execution_id": execution_id,
        "execution_commitment_digest": commitment_digest,
        "bundle_digest": bundle_digest,
        "profile_digest": profile_digest,
        "code_version": dict(code_version),
        "check_id": check_id,
        "inputs_digest": inputs_digest,
        "execution_status": execution_status,
        "result": {
            "status": result_status,
            "detail": result_detail[:1024],
            "duration_ms": result_duration_ms,
        },
        "witness": {
            "witness_mode": witness_mode,
            "witness_key_id": witness_key_id,
            "witness_software": witness_software,
        },
        "log_anchor": dict(log_anchor),
        "claimed_time": claimed_time,
        "limitations": [dict(lim) for lim in (limitations or MODEL_A_LIMITATIONS)],
    }
    if receipt_digest is not None:
        payload["receipt_digest"] = receipt_digest
    return payload


class LocalProcessWitness:
    """Client for a witness worker running as a separate process.

    Spawns ``python -m oev.witness_worker``; the private key file is read
    by the worker process only and never crosses into this process.
    """

    def __init__(
        self,
        private_key_path: str | Path,
        key_id: str,
        log_path: str | Path,
        log_id: str = "hea-log-001",
        timeout_seconds: float = 60.0,
        checkpoint_key_path: str | Path | None = None,
        checkpoint_key_id: str = "",
        witness_mode: str = "local-process",
    ) -> None:
        self._private_key_path = Path(private_key_path)
        self.key_id = key_id
        self.witness_mode = witness_mode
        self._log_path = Path(log_path)
        self._log_id = log_id
        self._timeout = timeout_seconds
        self._checkpoint_key_path = Path(checkpoint_key_path) if checkpoint_key_path else None
        self._checkpoint_key_id = checkpoint_key_id
        self._proc: subprocess.Popen[str] | None = None

    def __enter__(self: _WitnessT) -> _WitnessT:  # noqa: PYI019 - Self needs typing_extensions on py3.10; TypeVar keeps the runtime dependency-free
        import os

        env = dict(os.environ)
        worker_argv = [
            sys.executable,
            "-m",
            "oev.witness_worker",
            "--key",
            str(self._private_key_path),
            "--key-id",
            self.key_id,
            "--log",
            str(self._log_path),
            "--log-id",
            self._log_id,
            "--witness-mode",
            self.witness_mode,
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
            raise RuntimeError(f"Witness worker failed to start: {ready}")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._proc is not None:
            try:
                self._call("shutdown", {})
            except (RuntimeError, TimeoutError):
                pass  # best-effort shutdown; the worker may already be gone
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _call(self, op: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("Witness worker is not running")
        request = json.dumps({"op": op, **payload})
        self._proc.stdin.write(request + "\n")
        self._proc.stdin.flush()
        import select

        ready, _w, _x = select.select([self._proc.stdout], [], [], self._timeout)
        if not ready:
            raise TimeoutError(f"Witness worker did not respond to {op!r} within {self._timeout}s")
        line = self._proc.stdout.readline()
        if not line:
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"Witness worker closed stdout during {op!r}: {stderr[:500]}")
        response = json.loads(line)
        if not isinstance(response, dict) or not response.get("ok"):
            raise RuntimeError(
                f"Witness worker error for {op!r}: {response.get('error', response)}"
            )
        return response

    # Thin pass-throughs mirroring WitnessService ---------------------------
    def observe_file(self, path: str | Path) -> str:
        return str(self._call("observe_file", {"path": str(path)})["digest"])

    def observe_bytes(self, name: str, data: bytes) -> str:
        import base64

        return str(
            self._call(
                "observe_bytes",
                {"name": name, "data_b64": base64.b64encode(data).decode("ascii")},
            )["digest"]
        )

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


def is_valid_witness_log_id(log_id: str) -> bool:
    return bool(log_id) and len(log_id) <= 128 and all(c.isalnum() or c in "-_." for c in log_id)


# Re-exported for callers that build pre-bindings without importing execution.
__all__ = [
    "LocalProcessWitness",
    "WitnessService",
    "build_attestation_payload",
    "build_prebinding",
    "check_private_key_not_test_only",
    "compute_execution_id",
    "is_valid_execution_id",
    "is_valid_witness_log_id",
]

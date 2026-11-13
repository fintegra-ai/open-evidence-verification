# SPDX-License-Identifier: Apache-2.0

"""B2 witness worker process (Model B2, separate process).

Run as ``python -m oev.b2_worker --key <private-pem> --key-id <id>
--log <logfile.jsonl>``. Speaks JSON lines on stdin/stdout, like
``oev.witness_worker`` (Model A), plus one B2-only op::

    {"op": "reexecute", "package_b64": "...", "profile": {...},
     "package_trust_keys": [...]}
        -> {"ok": true, "checks": [...], "receipt_digest": "...",
            "overall_result": "..."}

The worker is the only holder of the witness private key: the key file
is read here, never sent to the parent. Re-execution happens *in this
process*, on the bytes it received — the producer's claimed results
never enter this process except through the caller's comparison.
A request that fails validation returns ``{"ok": false, "error": ...}``;
the worker keeps running so one bad request cannot kill the witness
mid-execution.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

from oev.b2_witness import B2ReexecutingWitness
from oev.models import VerificationProfile


def _handle(service: B2ReexecutingWitness, request: dict[str, Any]) -> dict[str, Any]:
    op = str(request.get("op", ""))
    if op == "ping":
        return {"ok": True, "key_id": service.key_id, "log_id": service.log_id}
    if op == "shutdown":
        return {"ok": True}
    if op == "receive_bundle":
        raw_package = base64.b64decode(str(request["package_b64"]).encode("ascii"), validate=True)
        raw_profile = base64.b64decode(str(request["profile_b64"]).encode("ascii"), validate=True)
        result = service.receive_bundle(raw_package, raw_profile)
        return {"ok": True, **result}
    if op == "code_digest":
        return {"ok": True, "code_digest": service.code_digest()}
    if op == "commit":
        result = service.issue_commitment(
            dict(request["prebinding"]), str(request["issued_at_claimed"])
        )
        return {"ok": True, **result}
    if op == "start":
        result = service.start_execution(
            str(request["execution_id"]),
            str(request["commitment_digest"]),
            str(request["claimed_time"]),
        )
        return {"ok": True, **result}
    if op == "check_completed":
        result = service.check_completed(
            str(request["execution_id"]),
            str(request["check_id"]),
            str(request["result_digest"]),
            str(request["claimed_time"]),
        )
        return {"ok": True, **result}
    if op == "complete":
        result = service.complete_execution(
            str(request["execution_id"]), str(request["status"]), str(request["claimed_time"])
        )
        return {"ok": True, **result}
    if op == "attest":
        envelope = service.attest(dict(request["payload"]))
        return {"ok": True, "envelope": envelope}
    if op == "checkpoint":
        result = service.checkpoint(str(request["claimed_time"]))
        return {"ok": True, **result}
    if op == "export_log":
        import base64 as _b64

        return {"ok": True, "log_b64": _b64.b64encode(service.export_log_jsonl()).decode("ascii")}
    if op == "reexecute":
        raw_package = base64.b64decode(str(request["package_b64"]).encode("ascii"), validate=True)
        profile = VerificationProfile.from_dict(dict(request["profile"]))
        result = service.reexecute(
            raw_package, profile, list(request.get("package_trust_keys") or [])
        )
        return {"ok": True, **result}
    return {"ok": False, "error": f"unknown op: {op!r}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oev.b2_worker")
    parser.add_argument("--key", required=True, help="Path to B2 witness Ed25519 private key PEM")
    parser.add_argument("--key-id", required=True, help="B2 witness key id")
    parser.add_argument(
        "--checkpoint-key",
        help="Path to checkpoint-signer Ed25519 private key PEM (role-separated)",
    )
    parser.add_argument("--checkpoint-key-id", default="", help="Checkpoint-signer key id")
    parser.add_argument("--log", required=True, help="Path to the JSONL execution log file")
    parser.add_argument("--log-id", default="hea-b2-log-001", help="Log identifier")
    args = parser.parse_args(argv)

    try:
        private_key_pem = Path(args.key).read_bytes()
        checkpoint_key_pem = Path(args.checkpoint_key).read_bytes() if args.checkpoint_key else None
        service = B2ReexecutingWitness(
            private_key_pem,
            key_id=args.key_id,
            log_id=args.log_id,
            log_path=args.log,
            checkpoint_private_key_pem=checkpoint_key_pem,
            checkpoint_key_id=args.checkpoint_key_id,
        )
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"B2 witness worker failed to start: {exc}\n")
        return 1

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            sys.stdout.write(json.dumps({"ok": False, "error": f"invalid JSON: {exc}"}) + "\n")
            sys.stdout.flush()
            continue
        if not isinstance(request, dict):
            sys.stdout.write(json.dumps({"ok": False, "error": "request is not an object"}) + "\n")
            sys.stdout.flush()
            continue
        try:
            response = _handle(service, request)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            response = {"ok": False, "error": str(exc)}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
        if str(request.get("op")) == "shutdown":
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())

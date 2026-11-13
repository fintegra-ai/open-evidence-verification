# SPDX-License-Identifier: Apache-2.0

"""Witness worker process (Model A, separate process).

Run as ``python -m oev.witness_worker --key <private-pem> --key-id <id>
--log <logfile.jsonl>``. Speaks JSON lines on stdin/stdout: one request
object per line, one response object per line::

    {"op": "ping"}                                    -> {"ok": true, ...}
    {"op": "commit", "prebinding": {...}, "issued_at_claimed": "..."}
    {"op": "observe_file", "path": "..."}             -> {"ok": true, "digest": "..."}
    {"op": "observe_bytes", "name": "...", "data_b64": "..."}
    {"op": "code_digest"}                             -> {"ok": true, "code_digest": "..."}
    {"op": "start", "execution_id": ..., "commitment_digest": ..., "claimed_time": ...}
    {"op": "check_completed", "execution_id": ..., "check_id": ..., "result_digest": ..., "claimed_time": ...}
    {"op": "complete", "execution_id": ..., "status": "COMPLETED|FAILED", "claimed_time": ...}
    {"op": "attest", "payload": {...}}                -> {"ok": true, "envelope": {...}}
    {"op": "checkpoint", "claimed_time": ...}         -> {"ok": true, "checkpoint": {...}, "envelope": {...}}
    {"op": "completeness", "checkpoint": {...}, "claimed_time": ...}
    {"op": "shutdown"}                                -> {"ok": true}

The worker is the only holder of the private key: the key file is read
here, never sent to the parent. A request that fails validation returns
``{"ok": false, "error": "..."}``; the worker keeps running so one bad
request cannot kill the witness mid-execution.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

from oev.execution_log import LogCheckpoint
from oev.witness import WitnessService


def _handle(service: WitnessService, request: dict[str, Any]) -> dict[str, Any]:
    op = str(request.get("op", ""))
    if op == "ping":
        return {"ok": True, "key_id": service.key_id, "log_id": service.log_id}
    if op == "shutdown":
        return {"ok": True}
    if op == "observe_file":
        return {"ok": True, "digest": service.observe_file(str(request["path"]))}
    if op == "observe_bytes":
        raw = base64.b64decode(str(request["data_b64"]).encode("ascii"), validate=True)
        return {"ok": True, "digest": service.observe_bytes(str(request["name"]), raw)}
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
    if op == "completeness":
        checkpoint = LogCheckpoint.from_dict(dict(request["checkpoint"]))
        result = service.completeness(checkpoint, str(request["claimed_time"]))
        return {"ok": True, **result}
    return {"ok": False, "error": f"unknown op: {op!r}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oev.witness_worker")
    parser.add_argument("--key", required=True, help="Path to witness Ed25519 private key PEM")
    parser.add_argument("--key-id", required=True, help="Witness key id")
    parser.add_argument(
        "--checkpoint-key",
        help="Path to checkpoint-signer Ed25519 private key PEM (role-separated)",
    )
    parser.add_argument("--checkpoint-key-id", default="", help="Checkpoint-signer key id")
    parser.add_argument("--log", required=True, help="Path to the JSONL execution log file")
    parser.add_argument("--log-id", default="hea-log-001", help="Log identifier")
    parser.add_argument(
        "--witness-mode",
        default="local-process",
        choices=["local-process", "separate-machine", "tee"],
        help="Witness mode recorded in commitments (default: local-process, Model A)",
    )
    args = parser.parse_args(argv)

    try:
        private_key_pem = Path(args.key).read_bytes()
        checkpoint_key_pem = Path(args.checkpoint_key).read_bytes() if args.checkpoint_key else None
        service = WitnessService(
            private_key_pem,
            key_id=args.key_id,
            log_id=args.log_id,
            log_path=args.log,
            checkpoint_private_key_pem=checkpoint_key_pem,
            checkpoint_key_id=args.checkpoint_key_id,
            witness_mode=args.witness_mode,
        )
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"witness worker failed to start: {exc}\n")
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

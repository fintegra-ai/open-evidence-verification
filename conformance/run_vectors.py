# SPDX-License-Identifier: Apache-2.0

"""Language-independent conformance vector runner (Faz C, NLnet plan v2).

Runs the vectors in ``conformance/vectors/`` against a verifier and emits a
machine-readable report. Two modes:

``--verifier builtin``
    The OEVP reference CLI (``oev.cli.main``) executes each vector in-process.

``--verifier "<command> {input}"``
    External-verifier contract (any language): the runner invokes the command
    with ``{input}`` replaced by the absolute path of the vector's
    ``input.json``. The verifier MUST print a single JSON object on stdout::

        {"vector_id": "<id>", "exit_code": <int>, "result": {<observed fields>}}

    File references inside ``input.json["inputs"]`` are repo-root-relative;
    the repo root is the directory three levels above the input file.

Comparison is fail-closed: the vector passes only if the observed exit code
equals ``expected.json["exit_code"]`` AND every key/value pair in
``expected.json["asserts"]`` matches the observed result object. Vectors
marked ``"status": "planned"`` in the manifest are skipped and counted.

Usage::

    python conformance/run_vectors.py run --verifier builtin
    python conformance/run_vectors.py run --verifier "./my-verifier {input}"
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTORS_DIR = REPO_ROOT / "conformance" / "vectors"
SUBPROCESS_TIMEOUT_SECONDS = 120


def load_manifest(vectors_dir: Path) -> dict[str, Any]:
    manifest = json.loads((vectors_dir / "manifest.json").read_text(encoding="utf-8"))
    return manifest  # type: ignore[no-any-return]


def _extract_json(stdout: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    start = stdout.find("{")
    if start < 0:
        raise ValueError(f"no JSON object found on stdout: {stdout[:120]!r}")
    obj, _end = decoder.raw_decode(stdout[start:])
    if not isinstance(obj, dict):
        raise TypeError("stdout JSON is not an object")
    return obj


def _verify_argv(vector: dict[str, Any]) -> list[str]:
    inputs = vector["inputs"]
    # NOTE: `oev verify` has no --json flag; it prints the receipt JSON first,
    # followed by human-readable footer lines. _extract_json reads the first
    # JSON object, which is the receipt.
    argv = ["verify", REPO_ROOT / inputs["package"], "--profile", REPO_ROOT / inputs["profile"]]
    if "package_trust_keys" in inputs:
        argv += ["--trust-keys", REPO_ROOT / inputs["package_trust_keys"]]
    return [str(a) for a in argv]


def _inspect_argv(vector: dict[str, Any]) -> list[str]:
    inputs = vector["inputs"]
    argv = ["inspect-receipt", REPO_ROOT / inputs["receipt"], "--json"]
    if "verifier_keys" in inputs:
        argv += ["--verifier-keys", REPO_ROOT / inputs["verifier_keys"]]
    return [str(a) for a in argv]


def _reverify_argv(vector: dict[str, Any]) -> list[str]:
    inputs = vector["inputs"]
    argv = [
        "reverify",
        REPO_ROOT / inputs["package"],
        REPO_ROOT / inputs["receipt"],
        "--profile",
        REPO_ROOT / inputs["profile"],
    ]
    if "package_trust_keys" in inputs:
        argv += ["--trust-keys", REPO_ROOT / inputs["package_trust_keys"]]
    argv += ["--json"]
    return [str(a) for a in argv]


def _pack_replay_argv(vector: dict[str, Any]) -> list[str]:
    inputs = vector["inputs"]
    argv = ["pack", "replay", REPO_ROOT / inputs["pack"]]
    if "pin" in inputs:
        pin = json.loads((REPO_ROOT / inputs["pin"]).read_text(encoding="utf-8"))
        argv += ["--expect-pack-digest", pin["pack_digest"]]
    argv += ["--json"]
    return [str(a) for a in argv]


def _pack_verify_argv(vector: dict[str, Any]) -> list[str]:
    inputs = vector["inputs"]
    argv = ["pack", "verify", REPO_ROOT / inputs["pack"]]
    if "pack_verifier_keys" in inputs:
        argv += ["--verifier-keys", REPO_ROOT / inputs["pack_verifier_keys"]]
    argv += ["--json"]
    return [str(a) for a in argv]


def _pack_receipt_argv(vector: dict[str, Any]) -> list[str]:
    inputs = vector["inputs"]
    argv = ["pack", "receipt", "verify", REPO_ROOT / inputs["pack_receipt"], "--json"]
    if "pack_verifier_keys" in inputs:
        argv += ["--verifier-keys", REPO_ROOT / inputs["pack_verifier_keys"]]
    if "pack" in inputs:
        argv += ["--pack", REPO_ROOT / inputs["pack"]]
    return [str(a) for a in argv]


_ARGV_BUILDERS = {
    "verify": _verify_argv,
    "inspect_receipt": _inspect_argv,
    "reverify": _reverify_argv,
    "pack_replay": _pack_replay_argv,
    "pack_verify": _pack_verify_argv,
    "pack_receipt_verify": _pack_receipt_argv,
}


def run_builtin(vector: dict[str, Any]) -> dict[str, Any]:
    from oev.cli import main as cli_main

    builder = _ARGV_BUILDERS[vector["action"]]
    argv = builder(vector)
    buffer = StringIO()
    with redirect_stdout(buffer):
        exit_code = int(cli_main(argv))
    return {
        "vector_id": vector["vector_id"],
        "exit_code": exit_code,
        "result": _extract_json(buffer.getvalue()),
    }


def run_external(vector: dict[str, Any], command: str) -> dict[str, Any]:
    input_path = DEFAULT_VECTORS_DIR / vector["vector_id"] / "input.json"
    resolved = [part.replace("{input}", str(input_path)) for part in shlex.split(command)]
    completed = subprocess.run(
        resolved,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
        check=False,
    )
    try:
        observed = _extract_json(completed.stdout)
    except ValueError:
        observed = {}
    if observed.get("vector_id") != vector["vector_id"]:
        observed = dict(observed, vector_id=observed.get("vector_id"))
    return {
        "vector_id": vector["vector_id"],
        "exit_code": observed.get("exit_code"),
        "result": observed.get("result", {}),
        "verifier_stderr_tail": completed.stderr[-400:],
    }


def compare(
    vector: dict[str, Any], expected: dict[str, Any], observed: dict[str, Any]
) -> dict[str, Any]:
    problems: list[str] = []
    if observed.get("exit_code") != expected.get("exit_code"):
        problems.append(
            f"exit_code: expected {expected.get('exit_code')}, observed {observed.get('exit_code')}"
        )
    result = observed.get("result", {})
    for key, want in expected.get("asserts", {}).items():
        got = result.get(key)
        if key == "checks" and isinstance(want, dict) and isinstance(got, list):
            # The receipt lists check objects; vectors assert the reduced
            # {check_id: status} map used by the conformance fixtures.
            got = {c.get("check_id"): c.get("status") for c in got if isinstance(c, dict)}
        if got != want:
            problems.append(f"{key}: expected {want!r}, observed {got!r}")
    return {
        "vector_id": vector["vector_id"],
        "action": vector["action"],
        "passed": not problems,
        "problems": problems,
    }


def build_evidence_pack(
    report: dict[str, Any], vector_manifest: dict[str, Any], pack_path: Path
) -> Path:
    """Package one conformance run as an OEPT bundle (Faz C+).

    The bundle carries the run report and the vector-set manifest so the run
    itself becomes verifiable evidence: ``oev verify`` accepts it as an
    oept-bundle/0.1 package, and its member digests bind the exact report
    bytes. Requires the ``oept`` package.
    """
    try:
        from oept.bundle import BundleBuilder
    except ImportError as exc:
        raise SystemExit(
            "Error: --evidence-pack requires the 'oept' package. "
            "Install with 'pip install oept' or 'pip install open-evidence-verification[oept]'."
        ) from exc
    builder = BundleBuilder(
        bundle_id="oev-conformance-evidence",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    # The bundle manifest schema requires these two members; the reference
    # fixtures use the same neutral empty bodies.
    builder.add_file("facts.json", b"[]")
    builder.add_file("provenance.json", b"[]")
    builder.add_file(
        "evidence/report.json",
        (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    builder.add_file(
        "evidence/vector-set-manifest.json",
        (json.dumps(vector_manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    pack_path.write_bytes(builder.build_zip_bytes())
    return pack_path


def execute(
    vectors_dir: Path,
    verifier: str,
    report_path: Path | None = None,
    only: str | None = None,
    evidence_pack: Path | None = None,
) -> int:
    manifest = load_manifest(vectors_dir)
    results: list[dict[str, Any]] = []
    for entry in manifest["vectors"]:
        if only is not None and entry["id"] != only:
            continue
        if entry["status"] != "active":
            results.append(
                {
                    "vector_id": entry["id"],
                    "action": entry["action"],
                    "passed": None,
                    "skipped": entry.get("reason", "planned"),
                }
            )
            continue
        vector = json.loads((vectors_dir / entry["id"] / "input.json").read_text(encoding="utf-8"))
        expected = json.loads(
            (vectors_dir / entry["id"] / "expected.json").read_text(encoding="utf-8")
        )
        try:
            observed = (
                run_builtin(vector) if verifier == "builtin" else run_external(vector, verifier)
            )
        except Exception as exc:  # noqa: BLE001 - a crashing verifier is a failed vector
            observed = {
                "vector_id": entry["id"],
                "exit_code": None,
                "result": {},
                "error": repr(exc),
            }
        results.append(compare(vector, expected, observed))

    passed = sum(1 for r in results if r.get("passed") is True)
    failed = sum(1 for r in results if r.get("passed") is False)
    skipped = sum(1 for r in results if r.get("passed") is None)
    try:
        from oev import __version__ as oev_version
    except ImportError:
        oev_version = None
    report = {
        "vector_set": manifest["vector_set"],
        "vector_set_version": manifest["version"],
        "verifier": verifier,
        "oev_version": oev_version,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "skipped_planned": skipped,
        },
        "results": results,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if report_path is not None:
        report_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if evidence_pack is not None:
        build_evidence_pack(report, manifest, evidence_pack)
    return 0 if failed == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oevp-conformance", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the vector set against a verifier")
    run.add_argument(
        "--verifier", default="builtin", help="'builtin' or a command template containing {input}"
    )
    run.add_argument("--vectors-dir", type=Path, default=DEFAULT_VECTORS_DIR)
    run.add_argument(
        "--report", type=Path, default=None, help="write the JSON report here (default: stdout)"
    )
    run.add_argument("--only", default=None, help="run a single vector by id")
    run.add_argument(
        "--evidence-pack",
        type=Path,
        default=None,
        help="also write the run as an OEPT bundle (verifiable with 'oev verify') at this path",
    )
    args = parser.parse_args(argv)
    return execute(args.vectors_dir, args.verifier, args.report, args.only, args.evidence_pack)


if __name__ == "__main__":
    sys.exit(main())

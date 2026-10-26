"""Generate the neutral decision-evidence example pack `demo-case-001` deterministically.

The example is fully synthetic (a fictional pump-station maintenance review) and
contains no finance workflows, finance rule packs, customer data, or receivable,
trade, or investigation data. Re-running this script regenerates the pack bytes
identically; only the fresh Ed25519 demo keypair (and therefore the DSSE
envelope) changes per run.

Usage (from repository root):
    python examples/make_example.py
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

from oev.canonical import canonicalize_json
from oev.decision_models import DECISION_PACK_PROTOCOL_VERSION
from oev.decision_pack import compute_rule_digest
from oev.signing import generate_ed25519_keypair

ROOT = Path(__file__).resolve().parent
EXAMPLE_DIR = ROOT / "demo-case-001"
SRC_DIR = ROOT / "_src_demo-case-001"

SENSOR_EXPORT_CSV = """observed_at,source,pressure_psi
2026-10-01T07:50:00Z,sensor-feed-A,86.1
2026-10-01T07:55:00Z,sensor-feed-A,87.4
"""

MAINTENANCE_POLICY_TXT = """Maintenance policy (synthetic demo document)
============================================
- Pressure limit for station P-42: 85 psi.
- Service is considered overdue after 180 days without maintenance.
- Readings above the limit must be reviewed by a maintenance lead.
"""


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_source_members() -> None:
    """Write the raw (pre-manifest) member files of the example pack."""
    if SRC_DIR.exists():
        shutil.rmtree(SRC_DIR)
    (SRC_DIR / "artifacts").mkdir(parents=True)
    (SRC_DIR / "artifacts" / "sensor-export.csv").write_text(SENSOR_EXPORT_CSV, encoding="utf-8")
    (SRC_DIR / "artifacts" / "maintenance-policy.txt").write_text(
        MAINTENANCE_POLICY_TXT, encoding="utf-8"
    )

    members: dict[str, dict[str, object]] = {}

    members["case.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "case_type": "field-maintenance-review",
        "title": "Pump station P-42 maintenance review (synthetic demo)",
        "description": (
            "Fully synthetic demonstration case: a maintenance dispatcher reviews a "
            "sensor reading and records a maintenance decision. All data is fictional."
        ),
        "opened_at": "2026-10-01T08:00:00Z",
        "closed_at": "2026-10-01T09:30:00Z",
        "originating_system": "oev-demo-generator/0.2",
        "notes": ["Synthetic example data - not derived from any real asset, person, or decision."],
    }

    members["facts.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "facts": [
            {
                "fact_id": "fact-001",
                "key": "sensor.pressure_reading",
                "value": "87.4",
                "value_type": "decimal_string",
                "unit": "psi",
                "source": "sensor-feed-A",
                "observed_at": "2026-10-01T07:55:00Z",
                "snapshot_source_id": "sensor-export-2026-10-01",
                "note": "Values requiring exact decimal representation are strings.",
            },
            {
                "fact_id": "fact-002",
                "key": "sensor.pressure_limit",
                "value": "85",
                "value_type": "decimal_string",
                "unit": "psi",
                "source": "maintenance-policy-document",
                "observed_at": "2026-10-01T08:00:00Z",
                "snapshot_source_id": "policy-snapshot-2026-10-01",
            },
            {
                "fact_id": "fact-003",
                "key": "sensor.calibration_flag_active",
                "value": False,
                "source": "sensor-feed-A",
                "observed_at": "2026-10-01T07:55:00Z",
                "snapshot_source_id": "sensor-export-2026-10-01",
            },
        ],
    }

    rule_pressure = {
        "rule_id": "pressure-above-limit",
        "rule_version": "1.1.0",
        "description": "Flags when the latest pressure reading exceeds the configured limit.",
        "condition": {
            "op": "gt",
            "args": [
                {"fact": "sensor.pressure_reading"},
                {"fact": "sensor.pressure_limit"},
            ],
        },
    }
    rule_service = {
        "rule_id": "service-overdue",
        "rule_version": "1.0.0",
        "description": "Flags when the last service date is older than the configured maximum.",
        "condition": {
            "op": "days_since_gt",
            "args": [
                {"fact": "maintenance.last_service_date"},
                {"param": "max_days_since_service"},
            ],
        },
    }
    rule_calibration = {
        "rule_id": "calibration-flag-active",
        "rule_version": "1.0.0",
        "description": "Flags when the sensor calibration flag is active.",
        "condition": {
            "op": "eq",
            "args": [{"fact": "sensor.calibration_flag_active"}, {"const": True}],
        },
    }
    rule_agreement = {
        "rule_id": "dual-source-agreement",
        "rule_version": "0.3.0",
        "description": "Requires two independent readings for agreement; defers to a reviewer.",
        "condition": {
            "op": "fact_count_gte",
            "args": [{"prefix": "sensor.pressure_reading"}, {"const": 2}],
        },
    }

    members["rule_runs.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "rule_runs": [
            {
                "run_id": "run-001",
                "rule": {**rule_pressure, "rule_digest": compute_rule_digest(rule_pressure)},
                "inputs": ["fact-001", "fact-002"],
                "outcome": "TRIGGERED",
                "detail": "Latest reading 87.4 psi is greater than limit 85 psi.",
                "executed_at": "2026-10-01T08:05:00Z",
                "executed_by": "oev-demo-rules/0.2",
            },
            {
                "run_id": "run-002",
                "rule": {**rule_service, "rule_digest": compute_rule_digest(rule_service)},
                "inputs": [],
                "outcome": "UNVERIFIABLE",
                "detail": (
                    "Required fact 'maintenance.last_service_date' was not recorded in "
                    "this snapshot; the run could not reach a conclusion."
                ),
                "executed_at": "2026-10-01T08:05:00Z",
                "executed_by": "oev-demo-rules/0.2",
            },
            {
                "run_id": "run-003",
                "rule": {
                    **rule_calibration,
                    "rule_digest": compute_rule_digest(rule_calibration),
                },
                "inputs": ["fact-003"],
                "outcome": "NOT_TRIGGERED",
                "detail": "Calibration flag is false.",
                "executed_at": "2026-10-01T08:05:00Z",
                "executed_by": "oev-demo-rules/0.2",
            },
            {
                "run_id": "run-004",
                "rule": {**rule_agreement, "rule_digest": compute_rule_digest(rule_agreement)},
                "inputs": ["fact-001"],
                "outcome": "REVIEW_REQUIRED",
                "detail": (
                    "Only one independent pressure source recorded; agreement check "
                    "requires human review."
                ),
                "executed_at": "2026-10-01T08:05:00Z",
                "executed_by": "oev-demo-rules/0.2",
            },
        ],
    }

    members["findings.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "findings": [
            {
                "finding_id": "finding-001",
                "rule_run_id": "run-001",
                "rule_id": "pressure-above-limit",
                "severity": "MEDIUM",
                "summary": "Latest pressure reading 87.4 psi exceeds the configured limit 85 psi.",
                "related_fact_ids": ["fact-001", "fact-002"],
                "created_at": "2026-10-01T08:05:00Z",
            }
        ],
    }

    members["review_actions.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "review_actions": [
            {
                "action_id": "review-001",
                "action_type": "ESCALATE",
                "actor": {
                    "actor_id": "reviewer-001",
                    "actor_type": "human",
                    "display_name": "Dispatcher (demo)",
                },
                "performed_at": "2026-10-01T08:15:00Z",
                "references_finding_ids": ["finding-001"],
                "note": "Escalated to the maintenance lead for human judgment.",
            },
            {
                "action_id": "review-002",
                "action_type": "APPROVE",
                "actor": {
                    "actor_id": "reviewer-002",
                    "actor_type": "human",
                    "display_name": "Maintenance Lead (demo)",
                },
                "performed_at": "2026-10-01T09:30:00Z",
                "references_finding_ids": ["finding-001"],
                "note": (
                    "Work order WO-2041 scheduled and pressure placed under monitoring. "
                    "This record captures that the action occurred; the pack does not "
                    "assert the decision was correct."
                ),
            },
        ],
    }

    members["timeline.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "events": [
            {
                "event_id": "evt-001",
                "sequence": 1,
                "event_type": "case.opened",
                "occurred_at": "2026-10-01T08:00:00Z",
                "actor": "oev-demo-generator/0.2",
                "summary": "Case opened after scheduled sensor export.",
            },
            {
                "event_id": "evt-002",
                "sequence": 2,
                "event_type": "facts.recorded",
                "occurred_at": "2026-10-01T08:00:00Z",
                "actor": "oev-demo-generator/0.2",
                "summary": "Three facts recorded from the snapshot sources.",
                "references": [
                    {"kind": "fact", "id": "fact-001"},
                    {"kind": "fact", "id": "fact-002"},
                    {"kind": "fact", "id": "fact-003"},
                ],
            },
            {
                "event_id": "evt-003",
                "sequence": 3,
                "event_type": "rule_runs.executed",
                "occurred_at": "2026-10-01T08:05:00Z",
                "actor": "oev-demo-rules/0.2",
                "summary": "Four rules executed against the recorded facts.",
                "references": [
                    {"kind": "rule_run", "id": "run-001"},
                    {"kind": "rule_run", "id": "run-002"},
                    {"kind": "rule_run", "id": "run-003"},
                    {"kind": "rule_run", "id": "run-004"},
                ],
            },
            {
                "event_id": "evt-004",
                "sequence": 4,
                "event_type": "finding.raised",
                "occurred_at": "2026-10-01T08:05:00Z",
                "actor": "oev-demo-rules/0.2",
                "summary": "Finding raised from run-001.",
                "references": [{"kind": "finding", "id": "finding-001"}],
            },
            {
                "event_id": "evt-005",
                "sequence": 5,
                "event_type": "review.escalated",
                "occurred_at": "2026-10-01T08:15:00Z",
                "actor": "reviewer-001",
                "summary": "Finding escalated to maintenance lead.",
                "references": [{"kind": "review_action", "id": "review-001"}],
            },
            {
                "event_id": "evt-006",
                "sequence": 6,
                "event_type": "review.approved",
                "occurred_at": "2026-10-01T09:30:00Z",
                "actor": "reviewer-002",
                "summary": "Maintenance lead approved with work order scheduled.",
                "references": [{"kind": "review_action", "id": "review-002"}],
            },
            {
                "event_id": "evt-007",
                "sequence": 7,
                "event_type": "case.closed",
                "occurred_at": "2026-10-01T09:30:00Z",
                "actor": "oev-demo-generator/0.2",
                "summary": "Case closed after the recorded review actions.",
            },
        ],
    }

    members["snapshot_context.json"] = {
        "protocol_version": DECISION_PACK_PROTOCOL_VERSION,
        "case_id": "demo-case-001",
        "snapshot_id": "snapshot-2026-10-01-001",
        "captured_at": "2026-10-01T08:00:00Z",
        "generator": {"software": "oev-demo-generator", "version": "0.2.0"},
        "sources": [
            {
                "source_id": "sensor-export-2026-10-01",
                "kind": "sensor_export",
                "digest": _sha256_file(SRC_DIR / "artifacts" / "sensor-export.csv"),
                "retrieved_at": "2026-10-01T08:00:00Z",
            },
            {
                "source_id": "policy-snapshot-2026-10-01",
                "kind": "policy_document",
                "digest": _sha256_file(SRC_DIR / "artifacts" / "maintenance-policy.txt"),
                "retrieved_at": "2026-10-01T08:00:00Z",
            },
        ],
        "parameters": {
            "max_days_since_service": 180,
            "pressure_readings_required_for_agreement": 2,
        },
        "notes": ["Synthetic snapshot for demonstration purposes."],
    }

    for name, doc in members.items():
        (SRC_DIR / name).write_bytes(canonicalize_json(doc))


def main() -> None:
    write_source_members()

    # Late import keeps the builder's import graph independent of the example tooling.
    from oev.decision_pack import build_pack, sign_pack_manifest, verify_pack

    if EXAMPLE_DIR.exists():
        shutil.rmtree(EXAMPLE_DIR)
    manifest = build_pack(
        src_dir=SRC_DIR,
        out_dir=EXAMPLE_DIR,
        pack_id="pack-demo-case-001",
        created_at="2026-10-01T10:00:00Z",
        creator_software="oev",
        creator_version="0.2.0",
    )

    private_pem, public_pem = generate_ed25519_keypair()
    sign_pack_manifest(
        pack_dir=EXAMPLE_DIR,
        private_key_pem=private_pem,
        key_id="demo-signer-2026-10",
    )
    (ROOT / "demo-case-001.verifier-keys.json").write_bytes(
        canonicalize_json(
            [{"key_id": "demo-signer-2026-10", "public_key_pem": public_pem.decode("utf-8")}]
        )
    )

    shutil.rmtree(SRC_DIR)

    result = verify_pack(EXAMPLE_DIR, trust_store=None)
    if result.overall != "PACK_VALID":
        print("ERROR: generated example failed verification:", result.to_dict())
        sys.exit(1)
    print(f"Example pack generated at {EXAMPLE_DIR}")
    print(f"Pack digest: {manifest.pack_digest}")


if __name__ == "__main__":
    main()

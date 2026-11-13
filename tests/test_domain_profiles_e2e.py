# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests: OEPT bundle -> OEVP verify for the three domain profiles.

Each profile gets a valid signed bundle (overall
``TECHNICAL_CHECKS_PASSED``) plus one rebuilt-and-re-signed bundle per
corruption class — the container stays valid, so only the domain check
under attack fails. A container-level tamper (byte flip, no re-sign)
is covered separately: there the mechanical ``member_digests`` check
fails first.

All data is synthetic / generated; keys are deterministic Ed25519 test
keys derived from SHA-256 seeds (same convention as
``benchmarks/common.py``). No real personal or financial data.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oev.adapters.oept import is_oept_available
from oev.engine import execute_verification
from oev.models import CheckStatus, OverallResult
from oev.profiles import load_profile
from tests.test_domain_profiles import (  # fixture builders shared with unit tests
    DATA_CSV,
    PRED_CSV,
    ai_members,
    ds_members,
    fin_members,
)

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")

PROFILES_DIR = Path(__file__).resolve().parents[1] / "profiles"


def _derive_key(seed: str) -> tuple[bytes, bytes]:
    raw = hashlib.sha256(f"domain-e2e-key:{seed}".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _build_signed_bundle(members: dict[str, bytes], bundle_id: str) -> tuple[bytes, list[dict]]:
    """Return (bundle bytes, trust keys) for a signed OEPT bundle.

    OEPT requires ``facts.json``, ``provenance.json`` and at least one
    ``evidence/`` member; these are neutral synthetic envelope members
    (the domain evidence lives under ``domain/``) and carry no domain
    claims of their own.
    """
    from oept.bundle import BundleBuilder
    from oept.signing import sign_manifest

    envelope = {
        "facts.json": _j({"synthetic": True, "bundle_id": bundle_id}),
        "provenance.json": _j(
            {"source": "synthetic-generator", "synthetic": True, "generator": "domain-e2e/1.0"}
        ),
        "evidence/report.txt": b"synthetic envelope evidence\n",
    }
    full_members = dict(envelope)
    full_members.update(members)

    priv_pem, pub_pem = _derive_key(bundle_id)
    builder = BundleBuilder(
        bundle_id=bundle_id,
        created_at="2026-11-13T00:00:00Z",
        key_id=f"domain-e2e-{bundle_id}",
    )
    for path in sorted(full_members):
        builder.add_file(path, full_members[path])
    sig = sign_manifest(builder.manifest_bytes(), priv_pem)
    trust_keys = [{"key_id": f"domain-e2e-{bundle_id}", "public_key_pem": pub_pem.decode()}]
    return builder.build_zip_bytes(sig), trust_keys


def _verify(members, profile_name, bundle_id):
    profile = load_profile(PROFILES_DIR / profile_name / "profile.json")
    bundle, trust_keys = _build_signed_bundle(members, bundle_id)
    receipt, _ = execute_verification(bundle, profile, package_trust_keys=trust_keys)
    return receipt


def _statuses(receipt) -> dict[str, str]:
    return {
        c.check_id: (c.status.value if isinstance(c.status, CheckStatus) else str(c.status))
        for c in receipt.checks
    }


def _j(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True).encode()


# ---------------------------------------------------------------------------
# Financial Evidence E2E
# ---------------------------------------------------------------------------


def test_fin_e2e_valid_bundle_passes() -> None:
    receipt = _verify(fin_members(), "financial-evidence", "fin-valid-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PASSED
    st = _statuses(receipt)
    assert st["fin.amount_match"] == "PASS"
    assert st["fin.payment_match"] == "PASS"
    assert st["fin.identity_match"] == "PASS"
    assert st["fin.supporting_document"] == "PASS"
    assert st["application_signature"] == "PASS"
    assert st["member_digests"] == "PASS"


def test_fin_e2e_amount_lie_fails_domain_only() -> None:
    members = fin_members()
    erp = json.loads(members["domain/financial/erp_record.json"])
    erp["amount_minor"] = 999999
    members["domain/financial/erp_record.json"] = _j(erp)
    receipt = _verify(members, "financial-evidence", "fin-amount-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    st = _statuses(receipt)
    assert st["fin.amount_match"] == "FAIL"
    assert st["member_digests"] == "PASS"  # container is valid; content lies


def test_fin_e2e_missing_optional_doc_is_partial_not_failed() -> None:
    members = fin_members()
    del members["domain/financial/supporting.json"]
    receipt = _verify(members, "financial-evidence", "fin-no-support-001")
    # Required checks all PASS; the optional supporting check was skipped.
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PARTIAL
    assert _statuses(receipt)["fin.supporting_document"] == "NOT_RUN"


def test_fin_e2e_missing_payment_is_unsatisfied_not_failed() -> None:
    members = fin_members()
    del members["domain/financial/payment.json"]
    receipt = _verify(members, "financial-evidence", "fin-no-payment-001")
    st = _statuses(receipt)
    assert st["fin.evidence_completeness"] == "FAIL"
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED


def test_fin_e2e_container_tamper_fails_digests() -> None:
    bundle, trust_keys = _build_signed_bundle(fin_members(), "fin-tamper-001")
    tampered = bytearray(bundle)
    tampered[-20] ^= 0xFF  # flip a byte inside the ZIP; no re-sign
    profile = load_profile(PROFILES_DIR / "financial-evidence" / "profile.json")
    receipt, _ = execute_verification(bytes(tampered), profile, package_trust_keys=trust_keys)
    assert _statuses(receipt)["member_digests"] in ("FAIL", "NOT_RUN")
    assert receipt.overall_result != OverallResult.TECHNICAL_CHECKS_PASSED


# ---------------------------------------------------------------------------
# Dataset Release E2E
# ---------------------------------------------------------------------------


def test_ds_e2e_valid_bundle_passes() -> None:
    receipt = _verify(ds_members(), "dataset-release", "ds-valid-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PASSED
    st = _statuses(receipt)
    assert st["ds.schema_integrity"] == "PASS"
    assert st["ds.row_count"] == "PASS"
    assert st["ds.checksum"] == "PASS"
    assert st["ds.version_match"] == "PASS"
    assert st["ds.data_dictionary"] == "PASS"


def test_ds_e2e_row_count_lie_fails() -> None:
    members = ds_members()
    man = json.loads(members["domain/dataset/manifest.json"])
    man["rows_declared"] = 1000
    members["domain/dataset/manifest.json"] = _j(man)
    receipt = _verify(members, "dataset-release", "ds-rows-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    assert _statuses(receipt)["ds.row_count"] == "FAIL"


def test_ds_e2e_checksum_lie_fails() -> None:
    members = ds_members()
    members["domain/dataset/data.csv"] = DATA_CSV + b"5,6.5,epsilon\n"
    receipt = _verify(members, "dataset-release", "ds-hash-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    st = _statuses(receipt)
    assert st["ds.checksum"] == "FAIL"
    assert st["ds.row_count"] == "FAIL"  # 5 rows now, 4 declared


def test_ds_e2e_schema_lie_fails() -> None:
    members = ds_members()
    members["domain/dataset/data.csv"] = (
        b"synth_a,synth_b,synth_c\n1,2.5,alpha\nXX,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"
    )
    man = json.loads(members["domain/dataset/manifest.json"])
    man["sha256"] = hashlib.sha256(members["domain/dataset/data.csv"]).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    receipt = _verify(members, "dataset-release", "ds-schema-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    assert _statuses(receipt)["ds.schema_integrity"] == "FAIL"


# ---------------------------------------------------------------------------
# AI Model Evaluation E2E
# ---------------------------------------------------------------------------


def test_ai_e2e_valid_bundle_passes() -> None:
    receipt = _verify(ai_members(), "ai-model-eval", "ai-valid-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PASSED
    st = _statuses(receipt)
    assert st["ai.metric_mae_agreement"] == "PASS"
    assert st["ai.metric_rmse_agreement"] == "PASS"
    assert st["ai.metric_r2_agreement"] == "PASS"
    assert st["ai.input_hash"] == "PASS"
    assert st["ai.execution_record"] == "PASS"
    assert st["ai.calibration"] == "PASS"


def test_ai_e2e_reported_metric_lie_fails() -> None:
    members = ai_members()
    ev = json.loads(members["domain/ai-eval/eval.json"])
    ev["reported"]["mae"] = 0.001  # recomputed MAE is 0.15
    ev["reported"]["r2"] = 0.999
    members["domain/ai-eval/eval.json"] = _j(ev)
    receipt = _verify(members, "ai-model-eval", "ai-metric-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    st = _statuses(receipt)
    assert st["ai.metric_mae_agreement"] == "FAIL"
    assert st["ai.metric_r2_agreement"] == "FAIL"
    assert st["ai.metric_rmse_agreement"] == "PASS"


def test_ai_e2e_input_hash_lie_fails() -> None:
    members = ai_members()
    members["domain/ai-eval/predictions.csv"] = PRED_CSV + b"5.0,5.0\n"
    receipt = _verify(members, "ai-model-eval", "ai-hash-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    st = _statuses(receipt)
    assert st["ai.input_hash"] == "FAIL"
    # The extra row also changes the recomputed metrics.
    assert st["ai.metric_mae_agreement"] == "FAIL"


def test_ai_e2e_execution_record_lie_fails() -> None:
    members = ai_members()
    members["domain/ai-eval/run.json"] = _j(
        {
            "model_id": "SYNTH-MODEL-01",
            "model_version": "0.3.0",
            "dataset_id": "SYNTH-DS-0001",
            "dataset_version": "2.0.0",  # eval says 1.2.0
            "run_id": "SYNTH-RUN-0001",
        }
    )
    receipt = _verify(members, "ai-model-eval", "ai-run-lie-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    assert _statuses(receipt)["ai.execution_record"] == "FAIL"


def test_ai_e2e_missing_optional_calibration_is_partial() -> None:
    members = ai_members()
    del members["domain/ai-eval/calibration.json"]
    receipt = _verify(members, "ai-model-eval", "ai-no-cal-001")
    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PARTIAL
    assert _statuses(receipt)["ai.calibration"] == "NOT_RUN"

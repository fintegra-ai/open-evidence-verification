# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the three real domain check engines (``oev.domain``).

All inputs are synthetic / generated; no real personal or financial
data. Each test drives an engine directly on a member dict and asserts
the exact CheckStatus — in particular that a skipped check (NOT_RUN)
and a failed check (FAIL) are never the same outcome.
"""

from __future__ import annotations

import hashlib
import json
import math

from oev.domain import evaluate_domain_checks
from oev.domain.ai_eval import AI_CHECK_IDS
from oev.domain.dataset import DATASET_CHECK_IDS
from oev.domain.financial import FINANCIAL_CHECK_IDS
from oev.models import CheckStatus, VerificationProfile


def _profile(check_ids: list[str]) -> VerificationProfile:
    return VerificationProfile(
        profile_id="test-domain",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=list(check_ids),
    )


def _statuses(results) -> dict[str, str]:
    return {
        r.check_id: (r.status.value if isinstance(r.status, CheckStatus) else str(r.status))
        for r in results
    }


def _run(members: dict[str, bytes], check_ids) -> dict[str, str]:
    return _statuses(evaluate_domain_checks(members, _profile(list(check_ids))))


def _j(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True).encode()


# ---------------------------------------------------------------------------
# Financial Evidence
# ---------------------------------------------------------------------------

FIN_ALL = list(FINANCIAL_CHECK_IDS)


def fin_members(**overrides) -> dict[str, bytes]:
    invoice = {
        "profile_version": "0.1.0",
        "invoice_no": "SYNTH-INV-0001",
        "seller_id": "SYNTH-SELLER-01",
        "buyer_id": "SYNTH-BUYER-01",
        "amount_minor": 123456,
        "currency": "XXX",
        "invoice_date": "2026-11-01",
        "payment_expected": True,
    }
    erp = {
        "invoice_no": "SYNTH-INV-0001",
        "seller_id": "SYNTH-SELLER-01",
        "buyer_id": "SYNTH-BUYER-01",
        "amount_minor": 123456,
        "currency": "XXX",
        "posting_date": "2026-11-02",
    }
    payment = {
        "invoice_no": "SYNTH-INV-0001",
        "seller_id": "SYNTH-SELLER-01",
        "buyer_id": "SYNTH-BUYER-01",
        "amount_minor": 123456,
        "currency": "XXX",
        "payment_date": "2026-11-03",
    }
    supporting = _j({"document_type": "synthetic delivery note", "ref": "SYNTH-DN-1"})
    invoice["supporting_sha256"] = hashlib.sha256(supporting).hexdigest()
    members = {
        "domain/financial/invoice.json": _j(invoice),
        "domain/financial/erp_record.json": _j(erp),
        "domain/financial/payment.json": _j(payment),
        "domain/financial/supporting.json": supporting,
    }
    for key, value in overrides.items():
        if value is None:
            members.pop(key, None)
        else:
            members[key] = value
    return members


def _fin_doc(members: dict[str, bytes], path: str) -> dict:
    return json.loads(members[path].decode())


def test_fin_valid_bundle_all_pass() -> None:
    assert _run(fin_members(), FIN_ALL) == {c: "PASS" for c in FIN_ALL}


def test_fin_amount_mismatch_is_fail() -> None:
    members = fin_members()
    erp = _fin_doc(members, "domain/financial/erp_record.json")
    erp["amount_minor"] = 123457  # one minor unit off
    members["domain/financial/erp_record.json"] = _j(erp)
    st = _run(members, FIN_ALL)
    assert st["fin.amount_match"] == "FAIL"
    assert st["fin.evidence_completeness"] == "PASS"
    assert st["fin.payment_match"] == "PASS"  # payment still matches invoice


def test_fin_payment_mismatch_is_fail() -> None:
    members = fin_members()
    pay = _fin_doc(members, "domain/financial/payment.json")
    pay["amount_minor"] = 100000
    members["domain/financial/payment.json"] = _j(pay)
    st = _run(members, FIN_ALL)
    assert st["fin.payment_match"] == "FAIL"
    assert st["fin.amount_match"] == "PASS"


def test_fin_identity_mismatch_is_fail() -> None:
    members = fin_members()
    erp = _fin_doc(members, "domain/financial/erp_record.json")
    erp["seller_id"] = "SYNTH-SELLER-99"
    members["domain/financial/erp_record.json"] = _j(erp)
    assert _run(members, FIN_ALL)["fin.identity_match"] == "FAIL"


def test_fin_currency_mismatch_is_fail() -> None:
    members = fin_members()
    pay = _fin_doc(members, "domain/financial/payment.json")
    pay["currency"] = "YYY"
    members["domain/financial/payment.json"] = _j(pay)
    assert _run(members, FIN_ALL)["fin.currency_match"] == "FAIL"


def test_fin_date_contradiction_is_fail() -> None:
    members = fin_members()
    pay = _fin_doc(members, "domain/financial/payment.json")
    pay["payment_date"] = "2026-10-01"  # before the invoice date
    members["domain/financial/payment.json"] = _j(pay)
    assert _run(members, FIN_ALL)["fin.date_consistency"] == "FAIL"


def test_fin_missing_payment_completeness_fail_but_dependents_not_run() -> None:
    st = _run(fin_members(**{"domain/financial/payment.json": None}), FIN_ALL)
    # The bundle claims complete evidence and fails that claim...
    assert st["fin.evidence_completeness"] == "FAIL"
    # ...while the checks that need the payment honestly never start.
    assert st["fin.payment_match"] == "NOT_RUN"
    # Checks computable from invoice + ERP still run.
    assert st["fin.amount_match"] == "PASS"
    assert st["fin.identity_match"] == "PASS"


def test_fin_missing_invoice_is_not_run_not_fail_for_dependents() -> None:
    st = _run(fin_members(**{"domain/financial/invoice.json": None}), FIN_ALL)
    assert st["fin.evidence_completeness"] == "FAIL"
    assert st["fin.amount_match"] == "NOT_RUN"
    assert st["fin.identity_match"] == "NOT_RUN"
    assert st["fin.currency_match"] == "NOT_RUN"
    assert st["fin.date_consistency"] == "NOT_RUN"


def test_fin_optional_supporting_absent_is_not_run() -> None:
    st = _run(fin_members(**{"domain/financial/supporting.json": None}), FIN_ALL)
    assert st["fin.supporting_document"] == "NOT_RUN"
    assert st["fin.amount_match"] == "PASS"


def test_fin_supporting_without_reference_is_unverified() -> None:
    members = fin_members()
    inv = _fin_doc(members, "domain/financial/invoice.json")
    del inv["supporting_sha256"]
    members["domain/financial/invoice.json"] = _j(inv)
    assert _run(members, FIN_ALL)["fin.supporting_document"] == "UNVERIFIED"


def test_fin_supporting_tampered_is_fail() -> None:
    members = fin_members()
    members["domain/financial/supporting.json"] = _j({"document_type": "forged"})
    assert _run(members, FIN_ALL)["fin.supporting_document"] == "FAIL"


def test_fin_proforma_payment_is_not_applicable() -> None:
    members = fin_members(**{"domain/financial/payment.json": None})
    inv = _fin_doc(members, "domain/financial/invoice.json")
    inv["kind"] = "proforma"
    inv["payment_expected"] = False
    members["domain/financial/invoice.json"] = _j(inv)
    st = _run(members, FIN_ALL)
    assert st["fin.payment_match"] == "NOT_APPLICABLE"
    assert st["fin.evidence_completeness"] == "PASS"
    assert st["fin.amount_match"] == "PASS"


def test_fin_unsupported_profile_version() -> None:
    members = fin_members()
    inv = _fin_doc(members, "domain/financial/invoice.json")
    inv["profile_version"] = "9.9"
    members["domain/financial/invoice.json"] = _j(inv)
    st = _run(members, FIN_ALL)
    assert st == {c: "UNSUPPORTED" for c in FIN_ALL}


def test_fin_non_integer_amount_is_fail_not_not_run() -> None:
    members = fin_members()
    inv = _fin_doc(members, "domain/financial/invoice.json")
    inv["amount_minor"] = "123456"  # string, not an integer minor-unit value
    members["domain/financial/invoice.json"] = _j(inv)
    st = _run(members, FIN_ALL)
    assert st["fin.amount_match"] == "FAIL"
    assert st["fin.payment_match"] == "FAIL"


def test_fin_unknown_domain_check_is_unsupported() -> None:
    st = _run(fin_members(), ["fin.not_a_real_check"])
    assert st == {"fin.not_a_real_check": "UNSUPPORTED"}


# ---------------------------------------------------------------------------
# Dataset Release
# ---------------------------------------------------------------------------

DS_ALL = list(DATASET_CHECK_IDS)

DATA_CSV = b"synth_a,synth_b,synth_c\n1,2.5,alpha\n2,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"


def ds_members(**overrides) -> dict[str, bytes]:
    manifest = {
        "profile_version": "0.1.0",
        "dataset_id": "SYNTH-DS-0001",
        "version": "1.2.0",
        "data_kind": "tabular",
        "columns": [
            {"name": "synth_a", "type": "integer"},
            {"name": "synth_b", "type": "number"},
            {"name": "synth_c", "type": "string"},
        ],
        "rows_declared": 4,
        "sha256": hashlib.sha256(DATA_CSV).hexdigest(),
        "checksum_algorithm": "sha256",
        "missing_threshold": 0.05,
    }
    members = {
        "domain/dataset/manifest.json": _j(manifest),
        "domain/dataset/data.csv": DATA_CSV,
        "domain/dataset/release.json": _j({"dataset_id": "SYNTH-DS-0001", "version": "1.2.0"}),
        "domain/dataset/dictionary.json": _j({"columns": ["synth_a", "synth_b", "synth_c"]}),
    }
    for key, value in overrides.items():
        if value is None:
            members.pop(key, None)
        else:
            members[key] = value
    return members


def _ds_doc(members: dict[str, bytes], path: str) -> dict:
    return json.loads(members[path].decode())


def test_ds_valid_bundle_all_pass() -> None:
    assert _run(ds_members(), DS_ALL) == {c: "PASS" for c in DS_ALL}


def test_ds_header_mismatch_is_fail() -> None:
    members = ds_members()
    members["domain/dataset/data.csv"] = (
        b"synth_a,synth_b,other\n1,2.5,alpha\n2,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"
    )
    # Re-declare the checksum so only the schema check can fail.
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(members["domain/dataset/data.csv"]).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    st = _run(members, DS_ALL)
    assert st["ds.schema_integrity"] == "FAIL"
    assert st["ds.checksum"] == "PASS"


def test_ds_wrong_cell_type_is_fail() -> None:
    members = ds_members()
    members["domain/dataset/data.csv"] = (
        b"synth_a,synth_b,synth_c\n1,2.5,alpha\nnot-an-int,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"
    )
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(members["domain/dataset/data.csv"]).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, DS_ALL)["ds.schema_integrity"] == "FAIL"


def test_ds_row_count_lie_is_fail() -> None:
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["rows_declared"] = 99
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, DS_ALL)["ds.row_count"] == "FAIL"


def test_ds_missing_value_rate_above_threshold_is_fail() -> None:
    members = ds_members()
    csv_bytes = b"synth_a,synth_b,synth_c\n1,,alpha\n2,,beta\n3,,gamma\n4,,delta\n"
    members["domain/dataset/data.csv"] = csv_bytes
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(csv_bytes).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    st = _run(members, DS_ALL)
    assert st["ds.missing_value_rate"] == "FAIL"  # 4/12 = 0.333 > 0.05
    assert st["ds.schema_integrity"] == "PASS"  # empty cells are not type errors


def test_ds_checksum_mismatch_is_fail() -> None:
    members = ds_members()
    members["domain/dataset/data.csv"] = DATA_CSV + b"5,6.5,epsilon\n"
    assert _run(members, DS_ALL)["ds.checksum"] == "FAIL"


def test_ds_checksum_undeclared_is_unverified() -> None:
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    del man["sha256"]
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, DS_ALL)["ds.checksum"] == "UNVERIFIED"


def test_ds_unknown_checksum_algorithm_is_unsupported() -> None:
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["checksum_algorithm"] = "blake3"
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, DS_ALL)["ds.checksum"] == "UNSUPPORTED"


def test_ds_version_mismatch_is_fail() -> None:
    members = ds_members()
    members["domain/dataset/release.json"] = _j({"dataset_id": "SYNTH-DS-0001", "version": "9.9.9"})
    assert _run(members, DS_ALL)["ds.version_match"] == "FAIL"


def test_ds_missing_release_is_not_run() -> None:
    st = _run(ds_members(**{"domain/dataset/release.json": None}), DS_ALL)
    assert st["ds.version_match"] == "NOT_RUN"
    assert st["ds.checksum"] == "PASS"


def test_ds_missing_data_file_is_not_run() -> None:
    st = _run(ds_members(**{"domain/dataset/data.csv": None}), DS_ALL)
    assert st["ds.schema_integrity"] == "NOT_RUN"
    assert st["ds.row_count"] == "NOT_RUN"
    assert st["ds.missing_value_rate"] == "NOT_RUN"
    assert st["ds.checksum"] == "NOT_RUN"


def test_ds_optional_dictionary_absent_is_not_run() -> None:
    st = _run(ds_members(**{"domain/dataset/dictionary.json": None}), DS_ALL)
    assert st["ds.data_dictionary"] == "NOT_RUN"
    assert st["ds.schema_integrity"] == "PASS"


def test_ds_dictionary_incomplete_is_fail() -> None:
    members = ds_members()
    members["domain/dataset/dictionary.json"] = _j({"columns": ["synth_a"]})
    assert _run(members, DS_ALL)["ds.data_dictionary"] == "FAIL"


def test_ds_text_dataset_schema_and_missing_are_not_applicable() -> None:
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["data_kind"] = "text"
    man["columns"] = None
    man["rows_declared"] = 2
    members["domain/dataset/manifest.json"] = _j(man)
    members["domain/dataset/data.csv"] = b"synthetic text record one\nsynthetic text record two\n"
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(members["domain/dataset/data.csv"]).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    members["domain/dataset/dictionary.json"] = _j({"columns": []})
    st = _run(members, DS_ALL)
    assert st["ds.schema_integrity"] == "NOT_APPLICABLE"
    assert st["ds.missing_value_rate"] == "NOT_APPLICABLE"
    assert st["ds.row_count"] == "PASS"
    assert st["ds.checksum"] == "PASS"


def test_ds_profile_threshold_beats_manifest_threshold() -> None:
    # 1 empty cell in 12 = 0.0833. The manifest allows 0.50, but the
    # verifier-side profile policy (0.05) must win.
    members = ds_members()
    csv_bytes = b"synth_a,synth_b,synth_c\n1,,alpha\n2,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"
    members["domain/dataset/data.csv"] = csv_bytes
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(csv_bytes).hexdigest()
    man["missing_threshold"] = 0.50
    members["domain/dataset/manifest.json"] = _j(man)
    profile = _profile(DS_ALL)
    profile.parameters["missing_threshold"] = 0.05
    st = _statuses(evaluate_domain_checks(members, profile))
    assert st["ds.missing_value_rate"] == "FAIL"


# ---------------------------------------------------------------------------
# AI Model Evaluation
# ---------------------------------------------------------------------------

AI_ALL = list(AI_CHECK_IDS)

# y_true, y_pred pairs chosen so the metrics are non-trivial:
# MAE = 0.15, RMSE = sqrt(0.025), R2 = 0.98 (computed in the test below
# with independent arithmetic, not by importing the engine's helpers).
PAIRS = [(1.0, 1.1), (2.0, 1.9), (3.0, 3.2), (4.0, 3.8)]
PRED_CSV = b"y_true,y_pred\n1.0,1.1\n2.0,1.9\n3.0,3.2\n4.0,3.8\n"


def _expected_metrics(pairs) -> tuple[float, float, float]:
    n = len(pairs)
    mae = sum(abs(t - p) for t, p in pairs) / n
    rmse = math.sqrt(sum((t - p) ** 2 for t, p in pairs) / n)
    mean = sum(t for t, _ in pairs) / n
    ss_tot = sum((t - mean) ** 2 for t, _ in pairs)
    ss_res = sum((t - p) ** 2 for t, p in pairs)
    return mae, rmse, 1.0 - ss_res / ss_tot


def ai_members(**overrides) -> dict[str, bytes]:
    mae, rmse, r2 = _expected_metrics(PAIRS)
    evaluation = {
        "profile_version": "0.1.0",
        "model_id": "SYNTH-MODEL-01",
        "model_version": "0.3.0",
        "dataset_id": "SYNTH-DS-0001",
        "dataset_version": "1.2.0",
        "input_source": "stored",
        "input_sha256": hashlib.sha256(PRED_CSV).hexdigest(),
        "reported": {"mae": mae, "rmse": rmse, "r2": r2},
    }
    members = {
        "domain/ai-eval/eval.json": _j(evaluation),
        "domain/ai-eval/predictions.csv": PRED_CSV,
        "domain/ai-eval/run.json": _j(
            {
                "model_id": "SYNTH-MODEL-01",
                "model_version": "0.3.0",
                "dataset_id": "SYNTH-DS-0001",
                "dataset_version": "1.2.0",
                "run_id": "SYNTH-RUN-0001",
            }
        ),
        "domain/ai-eval/calibration.json": _j(
            {"model_version": "0.3.0", "expected_calibration_error": 0.04}
        ),
    }
    for key, value in overrides.items():
        if value is None:
            members.pop(key, None)
        else:
            members[key] = value
    return members


def _ai_doc(members: dict[str, bytes], path: str) -> dict:
    return json.loads(members[path].decode())


def test_ai_valid_bundle_all_pass() -> None:
    mae, rmse, r2 = _expected_metrics(PAIRS)
    assert abs(mae - 0.15) < 1e-12
    assert abs(rmse - math.sqrt(0.025)) < 1e-12
    assert abs(r2 - 0.98) < 1e-12
    assert _run(ai_members(), AI_ALL) == {c: "PASS" for c in AI_ALL}


def test_ai_reported_mae_lie_is_fail() -> None:
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["reported"]["mae"] = 0.01  # recomputed MAE is 0.15
    members["domain/ai-eval/eval.json"] = _j(ev)
    st = _run(members, AI_ALL)
    assert st["ai.metric_mae_agreement"] == "FAIL"
    assert st["ai.metric_rmse_agreement"] == "PASS"
    assert st["ai.metric_r2_agreement"] == "PASS"


def test_ai_reported_rmse_and_r2_lies_are_fail() -> None:
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["reported"]["rmse"] = 0.99
    ev["reported"]["r2"] = 0.5
    members["domain/ai-eval/eval.json"] = _j(ev)
    st = _run(members, AI_ALL)
    assert st["ai.metric_rmse_agreement"] == "FAIL"
    assert st["ai.metric_r2_agreement"] == "FAIL"
    assert st["ai.metric_mae_agreement"] == "PASS"


def test_ai_missing_reported_metric_is_unverified() -> None:
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    del ev["reported"]["mae"]
    members["domain/ai-eval/eval.json"] = _j(ev)
    st = _run(members, AI_ALL)
    assert st["ai.metric_mae_agreement"] == "UNVERIFIED"
    assert st["ai.metric_rmse_agreement"] == "PASS"


def test_ai_missing_predictions_is_not_run() -> None:
    st = _run(ai_members(**{"domain/ai-eval/predictions.csv": None}), AI_ALL)
    assert st["ai.metric_mae_agreement"] == "NOT_RUN"
    assert st["ai.metric_rmse_agreement"] == "NOT_RUN"
    assert st["ai.metric_r2_agreement"] == "NOT_RUN"
    assert st["ai.input_hash"] == "NOT_RUN"


def test_ai_constant_y_true_r2_is_not_applicable() -> None:
    members = ai_members()
    csv_bytes = b"y_true,y_pred\n2.0,2.1\n2.0,1.9\n2.0,2.0\n2.0,2.2\n"
    members["domain/ai-eval/predictions.csv"] = csv_bytes
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    # R² is undefined for constant y_true; recompute MAE/RMSE only.
    pairs = [(2.0, 2.1), (2.0, 1.9), (2.0, 2.0), (2.0, 2.2)]
    mae = sum(abs(t - p) for t, p in pairs) / len(pairs)
    rmse = math.sqrt(sum((t - p) ** 2 for t, p in pairs) / len(pairs))
    ev["reported"] = {"mae": mae, "rmse": rmse}  # no r2: undefined
    ev["input_sha256"] = hashlib.sha256(csv_bytes).hexdigest()
    members["domain/ai-eval/eval.json"] = _j(ev)
    st = _run(members, AI_ALL)
    assert st["ai.metric_r2_agreement"] == "NOT_APPLICABLE"
    assert st["ai.metric_mae_agreement"] == "PASS"
    assert st["ai.metric_rmse_agreement"] == "PASS"


def test_ai_input_hash_mismatch_is_fail() -> None:
    members = ai_members()
    members["domain/ai-eval/predictions.csv"] = PRED_CSV + b"5.0,5.1\n"
    assert _run(members, AI_ALL)["ai.input_hash"] == "FAIL"


def test_ai_input_hash_undeclared_is_unverified() -> None:
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    del ev["input_sha256"]
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, AI_ALL)["ai.input_hash"] == "UNVERIFIED"


def test_ai_generated_inputs_hash_is_not_applicable() -> None:
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["input_source"] = "generated"
    del ev["input_sha256"]
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, AI_ALL)["ai.input_hash"] == "NOT_APPLICABLE"


def test_ai_execution_record_mismatch_is_fail() -> None:
    members = ai_members()
    members["domain/ai-eval/run.json"] = _j(
        {
            "model_id": "SYNTH-MODEL-01",
            "model_version": "0.4.0",  # eval says 0.3.0
            "dataset_id": "SYNTH-DS-0001",
            "dataset_version": "1.2.0",
            "run_id": "SYNTH-RUN-0001",
        }
    )
    assert _run(members, AI_ALL)["ai.execution_record"] == "FAIL"


def test_ai_missing_run_record_is_not_run() -> None:
    st = _run(ai_members(**{"domain/ai-eval/run.json": None}), AI_ALL)
    assert st["ai.execution_record"] == "NOT_RUN"
    assert st["ai.metric_mae_agreement"] == "PASS"


def test_ai_optional_calibration_absent_is_not_run() -> None:
    st = _run(ai_members(**{"domain/ai-eval/calibration.json": None}), AI_ALL)
    assert st["ai.calibration"] == "NOT_RUN"
    assert st["ai.metric_mae_agreement"] == "PASS"


def test_ai_calibration_error_above_ceiling_is_fail() -> None:
    members = ai_members()
    members["domain/ai-eval/calibration.json"] = _j(
        {"model_version": "0.3.0", "expected_calibration_error": 0.25}
    )
    assert _run(members, AI_ALL)["ai.calibration"] == "FAIL"


def test_ai_unsupported_profile_version() -> None:
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["profile_version"] = "2.0"
    members["domain/ai-eval/eval.json"] = _j(ev)
    st = _run(members, AI_ALL)
    assert st == {c: "UNSUPPORTED" for c in AI_ALL}


def test_ai_malformed_predictions_is_not_run() -> None:
    members = ai_members()
    members["domain/ai-eval/predictions.csv"] = b"not,a,valid,header\n1,2,3\n"
    st = _run(members, AI_ALL)
    assert st["ai.metric_mae_agreement"] == "NOT_RUN"
    assert st["ai.input_hash"] == "FAIL"  # hash still computable and mismatches


# ---------------------------------------------------------------------------
# Cross-profile: NOT_RUN vs FAIL is a real distinction in every profile
# ---------------------------------------------------------------------------


def test_not_run_and_fail_are_distinct_in_every_profile() -> None:
    # Skipped (input absent) -> NOT_RUN; corrupted (input present, rule
    # false) -> FAIL. The two must never coincide for the same check.
    fin_skipped = _run(
        fin_members(**{"domain/financial/payment.json": None}), ["fin.payment_match"]
    )
    fin_failed = _run(fin_members(), ["fin.payment_match"])
    assert fin_skipped["fin.payment_match"] == "NOT_RUN"
    assert fin_failed["fin.payment_match"] == "PASS"
    members = fin_members()
    pay = _fin_doc(members, "domain/financial/payment.json")
    pay["amount_minor"] = 1
    members["domain/financial/payment.json"] = _j(pay)
    assert _run(members, ["fin.payment_match"])["fin.payment_match"] == "FAIL"

    ds_skipped = _run(ds_members(**{"domain/dataset/data.csv": None}), ["ds.checksum"])
    assert ds_skipped["ds.checksum"] == "NOT_RUN"
    members = ds_members()
    members["domain/dataset/data.csv"] = DATA_CSV + b"9,9.9,extra\n"
    assert _run(members, ["ds.checksum"])["ds.checksum"] == "FAIL"

    ai_skipped = _run(
        ai_members(**{"domain/ai-eval/predictions.csv": None}),
        ["ai.metric_mae_agreement"],
    )
    assert ai_skipped["ai.metric_mae_agreement"] == "NOT_RUN"
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["reported"]["mae"] = 999.0
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, ["ai.metric_mae_agreement"])["ai.metric_mae_agreement"] == "FAIL"


def test_all_six_statuses_reachable_per_profile() -> None:
    # Financial: PASS (valid), FAIL (amount), NOT_RUN (optional doc),
    # NOT_APPLICABLE (proforma), UNVERIFIED (no reference digest),
    # UNSUPPORTED (version 9.9).
    assert _run(fin_members(), ["fin.amount_match"])["fin.amount_match"] == "PASS"
    members = fin_members()
    erp = _fin_doc(members, "domain/financial/erp_record.json")
    erp["amount_minor"] = 1
    members["domain/financial/erp_record.json"] = _j(erp)
    assert _run(members, ["fin.amount_match"])["fin.amount_match"] == "FAIL"
    assert (
        _run(
            fin_members(**{"domain/financial/supporting.json": None}), ["fin.supporting_document"]
        )["fin.supporting_document"]
        == "NOT_RUN"
    )
    members = fin_members(**{"domain/financial/payment.json": None})
    inv = _fin_doc(members, "domain/financial/invoice.json")
    inv["kind"] = "proforma"
    inv["payment_expected"] = False
    members["domain/financial/invoice.json"] = _j(inv)
    assert _run(members, ["fin.payment_match"])["fin.payment_match"] == "NOT_APPLICABLE"
    members = fin_members()
    inv = _fin_doc(members, "domain/financial/invoice.json")
    del inv["supporting_sha256"]
    members["domain/financial/invoice.json"] = _j(inv)
    assert _run(members, ["fin.supporting_document"])["fin.supporting_document"] == "UNVERIFIED"
    members = fin_members()
    inv = _fin_doc(members, "domain/financial/invoice.json")
    inv["profile_version"] = "9.9"
    members["domain/financial/invoice.json"] = _j(inv)
    assert _run(members, ["fin.amount_match"])["fin.amount_match"] == "UNSUPPORTED"

    # Dataset: PASS, FAIL, NOT_RUN, NOT_APPLICABLE (text), UNVERIFIED
    # (no checksum), UNSUPPORTED (blake3).
    assert _run(ds_members(), ["ds.checksum"])["ds.checksum"] == "PASS"
    members = ds_members()
    members["domain/dataset/data.csv"] = DATA_CSV + b"9,9.9,extra\n"
    assert _run(members, ["ds.checksum"])["ds.checksum"] == "FAIL"
    assert (
        _run(ds_members(**{"domain/dataset/data.csv": None}), ["ds.checksum"])["ds.checksum"]
        == "NOT_RUN"
    )
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["data_kind"] = "text"
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, ["ds.schema_integrity"])["ds.schema_integrity"] == "NOT_APPLICABLE"
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    del man["sha256"]
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, ["ds.checksum"])["ds.checksum"] == "UNVERIFIED"
    members = ds_members()
    man = _ds_doc(members, "domain/dataset/manifest.json")
    man["checksum_algorithm"] = "blake3"
    members["domain/dataset/manifest.json"] = _j(man)
    assert _run(members, ["ds.checksum"])["ds.checksum"] == "UNSUPPORTED"

    # AI eval: PASS, FAIL, NOT_RUN, NOT_APPLICABLE (constant y_true),
    # UNVERIFIED (no reported metric), UNSUPPORTED (version 2.0).
    assert _run(ai_members(), ["ai.metric_mae_agreement"])["ai.metric_mae_agreement"] == "PASS"
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["reported"]["mae"] = 999.0
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, ["ai.metric_mae_agreement"])["ai.metric_mae_agreement"] == "FAIL"
    assert (
        _run(ai_members(**{"domain/ai-eval/predictions.csv": None}), ["ai.metric_mae_agreement"])[
            "ai.metric_mae_agreement"
        ]
        == "NOT_RUN"
    )
    members = ai_members()
    csv_bytes = b"y_true,y_pred\n2.0,2.1\n2.0,1.9\n2.0,2.0\n2.0,2.2\n"
    members["domain/ai-eval/predictions.csv"] = csv_bytes
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["input_sha256"] = hashlib.sha256(csv_bytes).hexdigest()
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, ["ai.metric_r2_agreement"])["ai.metric_r2_agreement"] == "NOT_APPLICABLE"
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    del ev["reported"]["mae"]
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, ["ai.metric_mae_agreement"])["ai.metric_mae_agreement"] == "UNVERIFIED"
    members = ai_members()
    ev = _ai_doc(members, "domain/ai-eval/eval.json")
    ev["profile_version"] = "2.0"
    members["domain/ai-eval/eval.json"] = _j(ev)
    assert _run(members, ["ai.metric_mae_agreement"])["ai.metric_mae_agreement"] == "UNSUPPORTED"

# SPDX-License-Identifier: Apache-2.0

"""AI Model Evaluation domain checks (``ai.*``).

The reported metrics are NEVER taken at face value: MAE, RMSE and R²
are recomputed independently from the stored ``y_true``/``y_pred``
pairs (pure-stdlib arithmetic) and compared against the reported
values within a stated tolerance. No real model or evaluation data is
ever read; all inputs are synthetic.

Members (under ``domain/ai-eval/``):

- ``eval.json`` (required): ``model_id``, ``model_version``,
  ``dataset_id``, ``dataset_version``, ``input_source`` (``"stored"``
  default, ``"generated"``), optional ``input_sha256`` (hex SHA-256 of
  ``predictions.csv``), ``reported`` (object with any of ``mae``,
  ``rmse``, ``r2`` as numbers), ``profile_version``.
- ``predictions.csv`` (required): header ``y_true,y_pred`` + one row
  per evaluated item, both columns finite floats.
- ``run.json`` (required): ``model_version``, ``dataset_version``,
  ``run_id`` — the execution record the evaluation must agree with.
- ``calibration.json`` (optional): ``model_version``,
  ``expected_calibration_error`` (number, must be <= 0.10).

Tolerance for metric agreement: ``|recomputed - reported| <=
1e-9 + 1e-6 * |recomputed|``. A reported metric that is absent is
UNVERIFIED (the check ran, but there is no reported value to judge
against); a constant ``y_true`` makes R² undefined, so
``ai.metric_r2_agreement`` is NOT_APPLICABLE; a ``"generated"``
input source means there is no stored input file to hash, so
``ai.input_hash`` is NOT_APPLICABLE.
"""

from __future__ import annotations

import csv
import io
import math
from collections.abc import Callable
from typing import Any

from oev.domain.common import (
    load_json_member,
    result,
    sha256_hex,
    unsupported_results,
    version_supported,
)
from oev.models import CheckResult, CheckStatus

CATEGORY = "domain-ai-eval"
EVAL = "domain/ai-eval/eval.json"
PREDICTIONS = "domain/ai-eval/predictions.csv"
RUN = "domain/ai-eval/run.json"
CALIBRATION = "domain/ai-eval/calibration.json"

AI_CHECK_IDS: tuple[str, ...] = (
    "ai.metric_mae_agreement",
    "ai.metric_rmse_agreement",
    "ai.metric_r2_agreement",
    "ai.input_hash",
    "ai.execution_record",
    "ai.calibration",
)

ABS_TOL = 1e-9
REL_TOL = 1e-6
CALIBRATION_MAX_ERROR = 0.10


def _parse_predictions(
    raw: bytes,
) -> tuple[list[tuple[float, float]] | None, str | None]:
    """Return ``(pairs, error)``; malformed content is an error, not data."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, f"unparseable: {exc}"
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        return None, f"unparseable: {exc}"
    if not rows:
        return None, "empty predictions file (no header row)"
    if [h.strip() for h in rows[0]] != ["y_true", "y_pred"]:
        return None, f"header is {rows[0]}, expected ['y_true', 'y_pred']"
    pairs: list[tuple[float, float]] = []
    for line_no, row in enumerate(rows[1:], start=2):
        if len(row) != 2:
            return None, f"row {line_no}: {len(row)} cells, expected 2"
        try:
            y_true = float(row[0])
            y_pred = float(row[1])
        except ValueError:
            return None, f"row {line_no}: non-numeric value {row!r}"
        if not (math.isfinite(y_true) and math.isfinite(y_pred)):
            return None, f"row {line_no}: non-finite value {row!r}"
        pairs.append((y_true, y_pred))
    if not pairs:
        return None, "empty predictions file (no data rows)"
    return pairs, None


def _mae(pairs: list[tuple[float, float]]) -> float:
    return sum(abs(t - p) for t, p in pairs) / len(pairs)


def _rmse(pairs: list[tuple[float, float]]) -> float:
    return math.sqrt(sum((t - p) ** 2 for t, p in pairs) / len(pairs))


def _r2(pairs: list[tuple[float, float]]) -> float | None:
    """R², or None when y_true is constant (undefined: zero variance)."""
    mean = sum(t for t, _ in pairs) / len(pairs)
    ss_tot = sum((t - mean) ** 2 for t, _ in pairs)
    if ss_tot == 0.0:
        return None
    ss_res = sum((t - p) ** 2 for t, p in pairs)
    return 1.0 - ss_res / ss_tot


def evaluate_ai_eval(
    members: dict[str, bytes],
    requested: set[str],
    parameters: dict[str, Any] | None = None,
) -> list[CheckResult]:
    """Evaluate the requested ``ai.*`` checks over bundle ``members``.

    ``parameters`` is the verifier-side profile policy: metric
    tolerances (``metric_abs_tol`` / ``metric_rel_tol``) and the
    calibration ceiling (``calibration_max_error``) come from the
    profile, not from the bundle under verification.
    """
    params = parameters or {}
    abs_tol_raw = params.get("metric_abs_tol", ABS_TOL)
    rel_tol_raw = params.get("metric_rel_tol", REL_TOL)
    cal_max_raw = params.get("calibration_max_error", CALIBRATION_MAX_ERROR)
    abs_tol = float(abs_tol_raw) if isinstance(abs_tol_raw, (int, float)) else ABS_TOL
    rel_tol = float(rel_tol_raw) if isinstance(rel_tol_raw, (int, float)) else REL_TOL
    cal_max = float(cal_max_raw) if isinstance(cal_max_raw, (int, float)) else CALIBRATION_MAX_ERROR
    evaluation, _eval_err = load_json_member(members, EVAL)
    run, _run_err = load_json_member(members, RUN)
    calibration, _cal_err = load_json_member(members, CALIBRATION)
    pred_raw = members.get(PREDICTIONS)

    supported, declared = version_supported(evaluation)
    if not supported:
        return unsupported_results([c for c in AI_CHECK_IDS if c in requested], CATEGORY, declared)

    pairs: list[tuple[float, float]] | None = None
    pairs_err: str | None = None
    if pred_raw is not None:
        pairs, pairs_err = _parse_predictions(pred_raw)

    reported: dict[str, Any] = {}
    if evaluation is not None and isinstance(evaluation.get("reported"), dict):
        reported = evaluation["reported"]

    results: list[CheckResult] = []
    wanted = [c for c in AI_CHECK_IDS if c in requested]

    def _agree(recomputed: float, reported: float) -> bool:
        return abs(recomputed - reported) <= abs_tol + rel_tol * abs(recomputed)

    def metric_check(
        check_id: str,
        metric_name: str,
        recompute: Callable[[list[tuple[float, float]]], float | None],
    ) -> CheckResult:
        if pairs is None:
            cause = pairs_err or "predictions.csv missing"
            return result(
                check_id,
                CATEGORY,
                CheckStatus.NOT_RUN,
                f"Predictions absent/unreadable ({cause}); {metric_name} not recomputed",
            )
        value = recompute(pairs)
        if value is None:
            return result(
                check_id,
                CATEGORY,
                CheckStatus.NOT_APPLICABLE,
                "y_true is constant (zero variance); R² is undefined",
            )
        claimed = reported.get(metric_name)
        if claimed is None:
            return result(
                check_id,
                CATEGORY,
                CheckStatus.UNVERIFIED,
                f"No reported {metric_name} in eval.json to compare against "
                f"(recomputed {metric_name} = {value:.6f})",
            )
        if not isinstance(claimed, (int, float)) or isinstance(claimed, bool):
            return result(
                check_id,
                CATEGORY,
                CheckStatus.FAIL,
                f"Reported {metric_name} is not a number: {claimed!r}",
            )
        if _agree(value, float(claimed)):
            return result(
                check_id,
                CATEGORY,
                CheckStatus.PASS,
                f"Reported {metric_name} {claimed} agrees with recomputed "
                f"{value:.6f} (tol {abs_tol} abs + {rel_tol} rel)",
            )
        return result(
            check_id,
            CATEGORY,
            CheckStatus.FAIL,
            f"Reported {metric_name} {claimed} != recomputed {value:.6f}",
        )

    # -- ai.metric_mae_agreement / rmse / r2 -----------------------------
    if "ai.metric_mae_agreement" in wanted:
        results.append(metric_check("ai.metric_mae_agreement", "mae", _mae))
    if "ai.metric_rmse_agreement" in wanted:
        results.append(metric_check("ai.metric_rmse_agreement", "rmse", _rmse))
    if "ai.metric_r2_agreement" in wanted:
        results.append(metric_check("ai.metric_r2_agreement", "r2", _r2))

    # -- ai.input_hash -----------------------------------------------------
    if "ai.input_hash" in wanted:
        input_source = str(evaluation.get("input_source", "stored")) if evaluation else "stored"
        if input_source == "generated":
            results.append(
                result(
                    "ai.input_hash",
                    CATEGORY,
                    CheckStatus.NOT_APPLICABLE,
                    "Evaluation inputs are generated on the fly (input_source=generated); "
                    "there is no stored input file to hash",
                )
            )
        elif pred_raw is None:
            results.append(
                result(
                    "ai.input_hash",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "predictions.csv absent; nothing to hash",
                )
            )
        elif evaluation is None:
            results.append(
                result(
                    "ai.input_hash",
                    CATEGORY,
                    CheckStatus.UNVERIFIED,
                    "eval.json absent; no declared input hash to judge against",
                )
            )
        else:
            declared_hash = evaluation.get("input_sha256")
            if not isinstance(declared_hash, str) or not declared_hash:
                results.append(
                    result(
                        "ai.input_hash",
                        CATEGORY,
                        CheckStatus.UNVERIFIED,
                        "eval.json declares no input_sha256; input hash cannot be established",
                    )
                )
            elif sha256_hex(pred_raw) == declared_hash.lower():
                results.append(
                    result(
                        "ai.input_hash",
                        CATEGORY,
                        CheckStatus.PASS,
                        "predictions.csv SHA-256 matches the hash declared in eval.json",
                    )
                )
            else:
                results.append(
                    result(
                        "ai.input_hash",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "predictions.csv SHA-256 does not match the hash declared in eval.json",
                    )
                )

    # -- ai.execution_record -------------------------------------------------
    if "ai.execution_record" in wanted:
        if evaluation is None or run is None:
            results.append(
                result(
                    "ai.execution_record",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "eval.json or run.json absent/unreadable; execution record not started",
                )
            )
        else:
            mismatches: list[str] = []
            for field in ("model_id", "model_version", "dataset_id", "dataset_version"):
                if field in run and evaluation.get(field) != run.get(field):
                    mismatches.append(
                        f"{field}: eval {evaluation.get(field)!r} != run {run.get(field)!r}"
                    )
            if mismatches:
                results.append(
                    result(
                        "ai.execution_record",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Execution record mismatch: " + "; ".join(mismatches),
                    )
                )
            else:
                results.append(
                    result(
                        "ai.execution_record",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"eval.json agrees with run {run.get('run_id')!r} on "
                        "model/dataset identity and versions",
                    )
                )

    # -- ai.calibration (optional, skippable) --------------------------------
    if "ai.calibration" in wanted:
        if calibration is None:
            results.append(
                result(
                    "ai.calibration",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Optional calibration record absent; check skipped per profile",
                )
            )
        else:
            error = calibration.get("expected_calibration_error")
            problems: list[str] = []
            if not isinstance(error, (int, float)) or isinstance(error, bool):
                problems.append(f"expected_calibration_error is not a number: {error!r}")
            elif float(error) > cal_max:
                problems.append(f"expected_calibration_error {error} > {cal_max}")
            if (
                evaluation is not None
                and calibration.get("model_version") is not None
                and calibration.get("model_version") != evaluation.get("model_version")
            ):
                problems.append(
                    f"model_version {calibration.get('model_version')!r} != "
                    f"eval {evaluation.get('model_version')!r}"
                )
            if problems:
                results.append(
                    result(
                        "ai.calibration",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Calibration check failed: " + "; ".join(problems),
                    )
                )
            else:
                results.append(
                    result(
                        "ai.calibration",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"Expected calibration error {error} <= {cal_max}",
                    )
                )

    return results

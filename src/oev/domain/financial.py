# SPDX-License-Identifier: Apache-2.0

"""Financial Evidence domain checks (``fin.*``).

Real computation over synthetic bundle members — no real personal or
financial data. All amounts are integer minor units (kuruş/cents);
equality is exact, never floating-point.

Members (all JSON, under ``domain/financial/``):

- ``invoice.json`` (required): ``invoice_no``, ``seller_id``,
  ``buyer_id``, ``amount_minor`` (int), ``currency``, ``invoice_date``
  (``YYYY-MM-DD``), ``payment_expected`` (bool), optional
  ``supporting_sha256`` (hex SHA-256 of ``supporting.json``), optional
  ``kind`` (``"invoice"`` default, ``"proforma"``), ``profile_version``.
- ``erp_record.json`` (required): ``invoice_no``, ``seller_id``,
  ``buyer_id``, ``amount_minor``, ``currency``, ``posting_date``.
- ``payment.json`` (required iff ``payment_expected`` is true):
  ``invoice_no``, ``seller_id``, ``buyer_id``, ``amount_minor``,
  ``currency``, ``payment_date``.
- ``supporting.json`` (optional): any supporting document; when present
  its SHA-256 is compared against ``invoice.supporting_sha256``.

Missing-required-evidence rule (deliberate, documented): a missing
required member makes the *completeness* check FAIL — the bundle claims
a complete financial evidence set and that claim is false — while the
dependent computation checks honestly report NOT_RUN instead of
fabricating a verdict from absent inputs. A missing *optional*
supporting document makes ``fin.supporting_document`` NOT_RUN: the
profile defines that check as skippable.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from oev.domain.common import (
    is_int_value,
    load_json_member,
    result,
    sha256_hex,
    unsupported_results,
    version_supported,
)
from oev.models import CheckResult, CheckStatus

CATEGORY = "domain-financial"
INVOICE = "domain/financial/invoice.json"
ERP = "domain/financial/erp_record.json"
PAYMENT = "domain/financial/payment.json"
SUPPORTING = "domain/financial/supporting.json"

FINANCIAL_CHECK_IDS: tuple[str, ...] = (
    "fin.evidence_completeness",
    "fin.amount_match",
    "fin.payment_match",
    "fin.identity_match",
    "fin.currency_match",
    "fin.date_consistency",
    "fin.supporting_document",
)


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def evaluate_financial(
    members: dict[str, bytes],
    requested: set[str],
    parameters: dict[str, Any] | None = None,
) -> list[CheckResult]:
    """Evaluate the requested ``fin.*`` checks over bundle ``members``.

    ``parameters`` is accepted for dispatcher uniformity; the financial
    engine currently takes no verifier-side parameters (amounts are
    compared exactly, dates against the calendar).
    """
    _ = parameters
    invoice, invoice_err = load_json_member(members, INVOICE)
    erp, erp_err = load_json_member(members, ERP)
    payment, payment_err = load_json_member(members, PAYMENT)
    supporting = members.get(SUPPORTING)

    # Version gate: an explicitly declared unsupported profile version
    # makes every requested check UNSUPPORTED (no computation is run
    # under unknown semantics).
    supported, declared = version_supported(invoice)
    if not supported:
        return unsupported_results(
            [c for c in FINANCIAL_CHECK_IDS if c in requested], CATEGORY, declared
        )

    payment_expected = bool(invoice.get("payment_expected", True)) if invoice else True
    is_proforma = bool(invoice and invoice.get("kind") == "proforma")
    if is_proforma:
        payment_expected = False

    results: list[CheckResult] = []
    wanted = [c for c in FINANCIAL_CHECK_IDS if c in requested]

    # -- fin.evidence_completeness -------------------------------------
    if "fin.evidence_completeness" in wanted:
        missing: list[str] = []
        if invoice is None:
            missing.append(f"invoice.json ({invoice_err})")
        if erp is None:
            missing.append(f"erp_record.json ({erp_err})")
        if payment_expected and payment is None:
            missing.append(f"payment.json ({payment_err})")
        if missing:
            results.append(
                result(
                    "fin.evidence_completeness",
                    CATEGORY,
                    CheckStatus.FAIL,
                    "Required financial evidence missing: " + "; ".join(missing),
                )
            )
        else:
            results.append(
                result(
                    "fin.evidence_completeness",
                    CATEGORY,
                    CheckStatus.PASS,
                    "All required financial evidence members present",
                )
            )

    # Inputs missing/unreadable => dependent checks NOT_RUN (never a
    # fabricated verdict). Present-but-invalid fields => FAIL.
    # (mypy: the `is None` checks below also narrow the types.)

    # -- fin.amount_match ----------------------------------------------
    if "fin.amount_match" in wanted:
        if invoice is None or erp is None:
            results.append(
                result(
                    "fin.amount_match",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Invoice or ERP record absent/unreadable; amount comparison not started",
                )
            )
        elif not is_int_value(invoice.get("amount_minor")) or not is_int_value(
            erp.get("amount_minor")
        ):
            results.append(
                result(
                    "fin.amount_match",
                    CATEGORY,
                    CheckStatus.FAIL,
                    "amount_minor is not an integer minor-unit value in invoice or ERP record",
                )
            )
        elif invoice["amount_minor"] == erp["amount_minor"]:
            results.append(
                result(
                    "fin.amount_match",
                    CATEGORY,
                    CheckStatus.PASS,
                    f"Invoice amount == ERP amount ({invoice['amount_minor']} minor units)",
                )
            )
        else:
            results.append(
                result(
                    "fin.amount_match",
                    CATEGORY,
                    CheckStatus.FAIL,
                    f"Amount mismatch: invoice {invoice['amount_minor']} != "
                    f"ERP {erp['amount_minor']} (minor units)",
                )
            )

    # -- fin.payment_match ---------------------------------------------
    if "fin.payment_match" in wanted:
        if not payment_expected:
            results.append(
                result(
                    "fin.payment_match",
                    CATEGORY,
                    CheckStatus.NOT_APPLICABLE,
                    "No payment expected for this invoice "
                    "(payment_expected=false / pro-forma); no payment to match",
                )
            )
        elif invoice is None or payment is None:
            results.append(
                result(
                    "fin.payment_match",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Invoice or payment absent/unreadable; payment comparison not started",
                )
            )
        elif not is_int_value(invoice.get("amount_minor")) or not is_int_value(
            payment.get("amount_minor")
        ):
            results.append(
                result(
                    "fin.payment_match",
                    CATEGORY,
                    CheckStatus.FAIL,
                    "amount_minor is not an integer minor-unit value in invoice or payment",
                )
            )
        elif invoice["amount_minor"] == payment["amount_minor"]:
            results.append(
                result(
                    "fin.payment_match",
                    CATEGORY,
                    CheckStatus.PASS,
                    f"Payment amount == invoice amount ({invoice['amount_minor']} minor units)",
                )
            )
        else:
            results.append(
                result(
                    "fin.payment_match",
                    CATEGORY,
                    CheckStatus.FAIL,
                    f"Amount mismatch: invoice {invoice['amount_minor']} != "
                    f"payment {payment['amount_minor']} (minor units)",
                )
            )

    # -- fin.identity_match --------------------------------------------
    if "fin.identity_match" in wanted:
        docs = [("invoice", invoice), ("erp", erp)]
        if payment is not None:
            docs.append(("payment", payment))
        if invoice is None or erp is None:
            results.append(
                result(
                    "fin.identity_match",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Invoice or ERP record absent/unreadable; identity comparison not started",
                )
            )
        else:
            mismatches: list[str] = []
            for field in ("invoice_no", "seller_id", "buyer_id"):
                values = {name: d.get(field) for name, d in docs if d is not None}
                distinct = {str(v) for v in values.values()}
                if len(distinct) > 1:
                    mismatches.append(
                        f"{field}: " + ", ".join(f"{n}={v!r}" for n, v in values.items())
                    )
                elif any(v is None for v in values.values()):
                    mismatches.append(f"{field}: missing in one or more records")
            if mismatches:
                results.append(
                    result(
                        "fin.identity_match",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Identity mismatch: " + "; ".join(mismatches),
                    )
                )
            else:
                results.append(
                    result(
                        "fin.identity_match",
                        CATEGORY,
                        CheckStatus.PASS,
                        "seller_id, buyer_id and invoice_no agree across invoice, ERP"
                        + (" and payment" if payment is not None else ""),
                    )
                )

    # -- fin.currency_match --------------------------------------------
    if "fin.currency_match" in wanted:
        if invoice is None or erp is None:
            results.append(
                result(
                    "fin.currency_match",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Invoice or ERP record absent/unreadable; currency comparison not started",
                )
            )
        else:
            currencies = {"invoice": invoice.get("currency"), "erp": erp.get("currency")}
            if payment is not None:
                currencies["payment"] = payment.get("currency")
            distinct = {str(v) for v in currencies.values()}
            if len(distinct) > 1 or any(v is None for v in currencies.values()):
                results.append(
                    result(
                        "fin.currency_match",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Currency mismatch: "
                        + ", ".join(f"{n}={v!r}" for n, v in currencies.items()),
                    )
                )
            else:
                results.append(
                    result(
                        "fin.currency_match",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"Currency agrees across records ({invoice.get('currency')})",
                    )
                )

    # -- fin.date_consistency ------------------------------------------
    if "fin.date_consistency" in wanted:
        if invoice is None or erp is None:
            results.append(
                result(
                    "fin.date_consistency",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Invoice or ERP record absent/unreadable; date comparison not started",
                )
            )
        else:
            inv_date = _parse_date(invoice.get("invoice_date"))
            post_date = _parse_date(erp.get("posting_date"))
            pay_date = _parse_date(payment.get("payment_date")) if payment else None
            problems: list[str] = []
            if inv_date is None:
                problems.append("invoice_date is not a valid YYYY-MM-DD date")
            if post_date is None:
                problems.append("posting_date is not a valid YYYY-MM-DD date")
            if payment is not None and pay_date is None:
                problems.append("payment_date is not a valid YYYY-MM-DD date")
            if inv_date is not None and post_date is not None and inv_date > post_date:
                problems.append(f"invoice_date {inv_date} is after ERP posting_date {post_date}")
            if inv_date is not None and pay_date is not None and inv_date > pay_date:
                problems.append(f"invoice_date {inv_date} is after payment_date {pay_date}")
            if problems:
                results.append(
                    result(
                        "fin.date_consistency",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Date contradiction: " + "; ".join(problems),
                    )
                )
            else:
                results.append(
                    result(
                        "fin.date_consistency",
                        CATEGORY,
                        CheckStatus.PASS,
                        "invoice_date <= posting_date"
                        + (" <= payment_date" if pay_date is not None else ""),
                    )
                )

    # -- fin.supporting_document (optional, skippable) ------------------
    if "fin.supporting_document" in wanted:
        if supporting is None:
            results.append(
                result(
                    "fin.supporting_document",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Optional supporting document absent; check skipped per profile",
                )
            )
        else:
            reference = invoice.get("supporting_sha256") if invoice else None
            if not isinstance(reference, str) or not reference:
                results.append(
                    result(
                        "fin.supporting_document",
                        CATEGORY,
                        CheckStatus.UNVERIFIED,
                        "Supporting document present but invoice declares no "
                        "supporting_sha256 reference to judge it against",
                    )
                )
            elif sha256_hex(supporting) == reference.lower():
                results.append(
                    result(
                        "fin.supporting_document",
                        CATEGORY,
                        CheckStatus.PASS,
                        "Supporting document SHA-256 matches the digest declared in the invoice",
                    )
                )
            else:
                results.append(
                    result(
                        "fin.supporting_document",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Supporting document SHA-256 does not match the digest "
                        "declared in the invoice",
                    )
                )

    return results

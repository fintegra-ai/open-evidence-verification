# SPDX-License-Identifier: Apache-2.0

"""Domain check engines for OEVP verification profiles (``oev.domain``).

These engines implement the three real domain profiles of PUBLICATION_READINESS
§1 (previously only synthetic content differences in the benchmark
generator): financial evidence, dataset release, and AI model
evaluation. Each engine performs real computation over the bundle's
domain members — amounts are compared in integer minor units, dataset
rows/hashes are recomputed, and reported AI metrics are recomputed from
``y_true``/``y_pred`` and never taken at face value.

The engines are adapter-level: the OEVP core (``engine.py``,
``receipts.py``, ``models.py``) is untouched, and the OEPT adapter
dispatches to them when a profile requests a domain check id. A profile
document itself stays a plain ``oev-profile/0.1`` document; registering
one still requires no core change.

All inputs are synthetic / generated; no real personal or financial
data is ever read.
"""

from __future__ import annotations

from oev.domain.ai_eval import AI_CHECK_IDS, evaluate_ai_eval
from oev.domain.dataset import DATASET_CHECK_IDS, evaluate_dataset
from oev.domain.financial import FINANCIAL_CHECK_IDS, evaluate_financial
from oev.models import CheckResult, CheckStatus, VerificationProfile

#: Every check id implemented by the domain engines, by prefix.
DOMAIN_CHECK_IDS: frozenset[str] = frozenset(FINANCIAL_CHECK_IDS + DATASET_CHECK_IDS + AI_CHECK_IDS)

#: Prefix -> engine, for dispatch.
_DOMAIN_ENGINES = {
    "fin.": evaluate_financial,
    "ds.": evaluate_dataset,
    "ai.": evaluate_ai_eval,
}


def evaluate_domain_checks(
    members: dict[str, bytes],
    profile: VerificationProfile,
) -> list[CheckResult]:
    """Evaluate all domain checks requested by ``profile`` over ``members``.

    ``members`` maps bundle member path -> raw bytes (the bundle's ZIP
    contents, as read by the adapter). Checks not belonging to any known
    domain prefix are reported UNSUPPORTED here, so the caller never
    silently drops a requested check.
    """
    requested = set(profile.required_checks) | set(profile.optional_checks)
    results: list[CheckResult] = []
    by_prefix: dict[str, set[str]] = {}
    unknown: list[str] = []
    for check_id in sorted(requested):
        if check_id in DOMAIN_CHECK_IDS:
            for prefix in _DOMAIN_ENGINES:
                if check_id.startswith(prefix):
                    by_prefix.setdefault(prefix, set()).add(check_id)
                    break
        elif check_id.startswith(tuple(_DOMAIN_ENGINES)):
            # Domain-prefixed but not implemented: UNSUPPORTED, never silent.
            unknown.append(check_id)
    for prefix, engine in _DOMAIN_ENGINES.items():
        wanted = by_prefix.get(prefix)
        if wanted:
            results.extend(engine(members, wanted, dict(profile.parameters)))
    for check_id in unknown:
        results.append(
            CheckResult(
                check_id=check_id,
                category="domain",
                status=CheckStatus.UNSUPPORTED,
                detail=f"Domain check '{check_id}' is not implemented by this engine build",
            )
        )
    return results


__all__ = [
    "AI_CHECK_IDS",
    "DATASET_CHECK_IDS",
    "DOMAIN_CHECK_IDS",
    "FINANCIAL_CHECK_IDS",
    "evaluate_domain_checks",
]

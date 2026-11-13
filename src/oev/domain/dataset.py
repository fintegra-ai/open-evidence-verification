# SPDX-License-Identifier: Apache-2.0

"""Dataset Release domain checks (``ds.*``).

Real computation over synthetic bundle members: CSV parsing, strict
per-column type checks, row counting, missing-value rates, and SHA-256
verification. No real data is ever read.

Members (under ``domain/dataset/``):

- ``manifest.json`` (required): ``dataset_id``, ``version``,
  ``data_kind`` (``"tabular"`` default, ``"text"``), ``columns`` (list
  of ``{"name": ..., "type": "integer"|"number"|"string"}``, tabular
  only), ``rows_declared`` (int), optional ``sha256`` (hex SHA-256 of
  the data file), ``checksum_algorithm`` (default ``"sha256"``),
  ``missing_threshold`` (default ``0.05``), ``profile_version``.
- ``data.csv`` (required): the dataset file. Tabular: header row +
  data rows. Text: one record per non-empty line.
- ``release.json`` (required): ``dataset_id``, ``version`` — the
  release tag the manifest must agree with.
- ``dictionary.json`` (optional): ``{"columns": [...names...]}`` —
  every declared column must be documented.

``NOT_APPLICABLE`` arises honestly here: for a ``text`` dataset there
are no columns and no tabular cells, so ``ds.schema_integrity`` and
``ds.missing_value_rate`` do not apply. ``UNVERIFIED`` is the
manifest declaring no checksum to judge the file against;
``UNSUPPORTED`` is a declared checksum algorithm this engine does not
implement (anything other than ``sha256``).
"""

from __future__ import annotations

import csv
import io
from typing import Any

from oev.domain.common import (
    load_json_member,
    result,
    sha256_hex,
    unsupported_results,
    version_supported,
)
from oev.models import CheckResult, CheckStatus

CATEGORY = "domain-dataset"
MANIFEST = "domain/dataset/manifest.json"
DATA = "domain/dataset/data.csv"
RELEASE = "domain/dataset/release.json"
DICTIONARY = "domain/dataset/dictionary.json"

DATASET_CHECK_IDS: tuple[str, ...] = (
    "ds.schema_integrity",
    "ds.row_count",
    "ds.missing_value_rate",
    "ds.checksum",
    "ds.version_match",
    "ds.data_dictionary",
)


def _cell_matches_type(cell: str, col_type: str) -> bool:
    if cell == "":
        return True  # empty cells are counted by ds.missing_value_rate, not here
    if col_type == "integer":
        try:
            int(cell.strip())
        except ValueError:
            return False
        return True
    if col_type == "number":
        try:
            float(cell)
        except ValueError:
            return False
        return True
    # Unknown declared type: the schema itself is invalid.
    return col_type == "string"


def _read_csv_rows(raw: bytes) -> tuple[list[list[str]] | None, str | None]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, f"unparseable: {exc}"
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        return None, f"unparseable: {exc}"
    return rows, None


def evaluate_dataset(
    members: dict[str, bytes],
    requested: set[str],
    parameters: dict[str, Any] | None = None,
) -> list[CheckResult]:
    """Evaluate the requested ``ds.*`` checks over bundle ``members``.

    ``parameters`` is the verifier-side profile policy (thresholds).
    The missing-value threshold is taken from the profile parameters
    first; only if the profile declares none does the bundle manifest's
    own threshold apply, then the 0.05 default. A producer-declared
    threshold therefore cannot silently weaken verification.
    """
    manifest, manifest_err = load_json_member(members, MANIFEST)
    release, _release_err = load_json_member(members, RELEASE)
    dictionary, _dict_err = load_json_member(members, DICTIONARY)
    data_raw = members.get(DATA)

    supported, declared = version_supported(manifest)
    if not supported:
        return unsupported_results(
            [c for c in DATASET_CHECK_IDS if c in requested], CATEGORY, declared
        )

    data_kind = str(manifest.get("data_kind", "tabular")) if manifest else "tabular"
    is_text = data_kind == "text"
    rows: list[list[str]] | None = None
    rows_err: str | None = None
    if data_raw is not None:
        rows, rows_err = _read_csv_rows(data_raw)

    results: list[CheckResult] = []
    wanted = [c for c in DATASET_CHECK_IDS if c in requested]

    # -- ds.schema_integrity -------------------------------------------
    if "ds.schema_integrity" in wanted:
        if is_text:
            results.append(
                result(
                    "ds.schema_integrity",
                    CATEGORY,
                    CheckStatus.NOT_APPLICABLE,
                    "Text dataset has no columns; column schema does not apply",
                )
            )
        elif manifest is None or data_raw is None or rows is None:
            cause = manifest_err or rows_err or "data.csv missing"
            results.append(
                result(
                    "ds.schema_integrity",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    f"Manifest or data file absent/unreadable ({cause}); schema check not started",
                )
            )
        else:
            columns = manifest.get("columns")
            problems: list[str] = []
            if not isinstance(columns, list) or not columns:
                problems.append("manifest declares no columns")
            else:
                expected = [str(c.get("name")) for c in columns if isinstance(c, dict)]
                if not rows:
                    problems.append("data file is empty (no header row)")
                elif rows[0] != expected:
                    problems.append(f"header mismatch: file {rows[0]} != declared {expected}")
                else:
                    for r_no, row in enumerate(rows[1:], start=2):
                        if len(row) != len(expected):
                            problems.append(
                                f"row {r_no}: {len(row)} cells, expected {len(expected)}"
                            )
                            continue
                        for col, cell in zip(columns, row):
                            if isinstance(col, dict) and not _cell_matches_type(
                                cell, str(col.get("type", "string"))
                            ):
                                problems.append(
                                    f"row {r_no} col {col.get('name')!r}: "
                                    f"value {cell!r} is not {col.get('type')}"
                                )
            if problems:
                results.append(
                    result(
                        "ds.schema_integrity",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Schema violation: " + "; ".join(problems[:10]),
                    )
                )
            else:
                results.append(
                    result(
                        "ds.schema_integrity",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"Header and {len(rows) - 1} data rows match declared schema "
                        f"({len(expected)} columns)",
                    )
                )

    # -- ds.row_count ----------------------------------------------------
    if "ds.row_count" in wanted:
        if manifest is None or data_raw is None or rows is None:
            cause = manifest_err or rows_err or "data.csv missing"
            results.append(
                result(
                    "ds.row_count",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    f"Manifest or data file absent/unreadable ({cause}); row count not started",
                )
            )
        else:
            declared_rows = manifest.get("rows_declared")
            if is_text:
                actual = sum(1 for r in rows if r and any(c.strip() for c in r))
            else:
                actual = len(rows) - 1 if rows else 0
            if not isinstance(declared_rows, int) or isinstance(declared_rows, bool):
                results.append(
                    result(
                        "ds.row_count",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "rows_declared is not an integer in the manifest",
                    )
                )
            elif actual == declared_rows:
                results.append(
                    result(
                        "ds.row_count",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"Row count matches declaration ({actual} rows)",
                    )
                )
            else:
                results.append(
                    result(
                        "ds.row_count",
                        CATEGORY,
                        CheckStatus.FAIL,
                        f"Row count mismatch: declared {declared_rows}, actual {actual}",
                    )
                )

    # -- ds.missing_value_rate -------------------------------------------
    if "ds.missing_value_rate" in wanted:
        if is_text:
            results.append(
                result(
                    "ds.missing_value_rate",
                    CATEGORY,
                    CheckStatus.NOT_APPLICABLE,
                    "Text dataset has no tabular cells; missing-value rate does not apply",
                )
            )
        elif manifest is None or data_raw is None or rows is None:
            cause = manifest_err or rows_err or "data.csv missing"
            results.append(
                result(
                    "ds.missing_value_rate",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    f"Manifest or data file absent/unreadable ({cause}); "
                    "missing-value rate not started",
                )
            )
        else:
            data_rows = rows[1:] if rows else []
            total = sum(len(r) for r in data_rows)
            empty = sum(1 for r in data_rows for c in r if c == "")
            rate = (empty / total) if total else 0.0
            threshold = 0.05
            policy = (parameters or {}).get("missing_threshold")
            if isinstance(policy, (int, float)) and not isinstance(policy, bool):
                threshold = float(policy)
            else:
                declared_threshold = manifest.get("missing_threshold")
                if isinstance(declared_threshold, (int, float)) and not isinstance(
                    declared_threshold, bool
                ):
                    threshold = float(declared_threshold)
            if rate <= float(threshold):
                results.append(
                    result(
                        "ds.missing_value_rate",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"Missing-value rate {rate:.4f} ({empty}/{total} cells) "
                        f"<= threshold {threshold}",
                    )
                )
            else:
                results.append(
                    result(
                        "ds.missing_value_rate",
                        CATEGORY,
                        CheckStatus.FAIL,
                        f"Missing-value rate {rate:.4f} ({empty}/{total} cells) "
                        f"> threshold {threshold}",
                    )
                )

    # -- ds.checksum -------------------------------------------------------
    if "ds.checksum" in wanted:
        if data_raw is None:
            results.append(
                result(
                    "ds.checksum",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Data file absent; nothing to hash",
                )
            )
        elif manifest is None:
            results.append(
                result(
                    "ds.checksum",
                    CATEGORY,
                    CheckStatus.UNVERIFIED,
                    f"Manifest absent ({manifest_err}); no declared checksum to judge against",
                )
            )
        else:
            algorithm = str(manifest.get("checksum_algorithm", "sha256"))
            declared_hash = manifest.get("sha256")
            if algorithm != "sha256":
                results.append(
                    result(
                        "ds.checksum",
                        CATEGORY,
                        CheckStatus.UNSUPPORTED,
                        f"Checksum algorithm {algorithm!r} is not implemented "
                        "by this engine (supports: sha256)",
                    )
                )
            elif not isinstance(declared_hash, str) or not declared_hash:
                results.append(
                    result(
                        "ds.checksum",
                        CATEGORY,
                        CheckStatus.UNVERIFIED,
                        "Manifest declares no sha256 for the data file; "
                        "checksum cannot be established",
                    )
                )
            elif sha256_hex(data_raw) == declared_hash.lower():
                results.append(
                    result(
                        "ds.checksum",
                        CATEGORY,
                        CheckStatus.PASS,
                        "Data file SHA-256 matches the manifest declaration",
                    )
                )
            else:
                results.append(
                    result(
                        "ds.checksum",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Data file SHA-256 does not match the manifest declaration",
                    )
                )

    # -- ds.version_match --------------------------------------------------
    if "ds.version_match" in wanted:
        if manifest is None or release is None:
            results.append(
                result(
                    "ds.version_match",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Manifest or release record absent/unreadable; version comparison not started",
                )
            )
        else:
            mismatches: list[str] = []
            if manifest.get("version") != release.get("version"):
                mismatches.append(
                    f"version: manifest {manifest.get('version')!r} != "
                    f"release {release.get('version')!r}"
                )
            if manifest.get("dataset_id") != release.get("dataset_id"):
                mismatches.append(
                    f"dataset_id: manifest {manifest.get('dataset_id')!r} != "
                    f"release {release.get('dataset_id')!r}"
                )
            if mismatches:
                results.append(
                    result(
                        "ds.version_match",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Version mismatch: " + "; ".join(mismatches),
                    )
                )
            else:
                results.append(
                    result(
                        "ds.version_match",
                        CATEGORY,
                        CheckStatus.PASS,
                        f"Manifest and release agree: {manifest.get('dataset_id')} "
                        f"version {manifest.get('version')}",
                    )
                )

    # -- ds.data_dictionary (optional, skippable) --------------------------
    if "ds.data_dictionary" in wanted:
        if dictionary is None:
            results.append(
                result(
                    "ds.data_dictionary",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Optional data dictionary absent; check skipped per profile",
                )
            )
        elif manifest is None:
            results.append(
                result(
                    "ds.data_dictionary",
                    CATEGORY,
                    CheckStatus.NOT_RUN,
                    "Manifest absent; dictionary cannot be judged",
                )
            )
        else:
            columns = manifest.get("columns")
            documented = dictionary.get("columns")
            if not isinstance(columns, list):
                results.append(
                    result(
                        "ds.data_dictionary",
                        CATEGORY,
                        CheckStatus.NOT_APPLICABLE,
                        "Text dataset declares no columns; dictionary does not apply",
                    )
                )
            elif not isinstance(documented, list):
                results.append(
                    result(
                        "ds.data_dictionary",
                        CATEGORY,
                        CheckStatus.FAIL,
                        "Data dictionary does not list columns",
                    )
                )
            else:
                expected_names = {str(c.get("name")) for c in columns if isinstance(c, dict)}
                missing = sorted(expected_names - {str(c) for c in documented})
                if missing:
                    results.append(
                        result(
                            "ds.data_dictionary",
                            CATEGORY,
                            CheckStatus.FAIL,
                            "Undocumented columns: " + ", ".join(missing),
                        )
                    )
                else:
                    results.append(
                        result(
                            "ds.data_dictionary",
                            CATEGORY,
                            CheckStatus.PASS,
                            f"All {len(expected_names)} declared columns are documented",
                        )
                    )

    return results

# SPDX-License-Identifier: Apache-2.0

"""Open/closed boundary guard (Faz A, NLnet plan v2 — gate A).

The open core must build and test without any closed-repository code:

1. no module of the closed ecosystem (EvidenceOS and friends) may appear as
   an import target anywhere in this repository's Python sources, and
2. BOUNDARY.md must stay present so the classification cannot silently
   disappear.

The closed side consumes this package only as a pinned PyPI distribution;
vendoring checks live in the closed repository's CI, not here.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Import targets owned by the closed ecosystem. Extend this list together
#: with BOUNDARY.md §1 — never by weakening the test.
CLOSED_MODULE_NAMES: frozenset[str] = frozenset(
    {
        "evidenceos",
        "evidenceos_core",
        "evidenceos_finance",
        "amanah",
        "muhasebe",
        "payment_verification",
        "eu_cii_invoice_parser",
    }
)

#: Source roots scanned for imports (relative to REPO_ROOT).
SCAN_ROOTS: tuple[str, ...] = ("src", "tests", "conformance", "examples")


def _iter_python_files() -> list[Path]:
    paths: list[Path] = []
    for root in SCAN_ROOTS:
        base = REPO_ROOT / root
        if base.is_dir():
            paths.extend(sorted(base.rglob("*.py")))
    paths.extend(sorted(REPO_ROOT.glob("*.py")))
    return paths


def _imported_names(tree: ast.AST) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name.split(".")[0], node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.module.split(".")[0], node.lineno))
    return found


def test_boundary_doc_is_present() -> None:
    boundary = REPO_ROOT / "BOUNDARY.md"
    assert boundary.is_file(), "BOUNDARY.md is missing; the open/closed classification is normative"


def test_no_closed_module_is_imported() -> None:
    violations: list[str] = []
    for path in _iter_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for name, lineno in _imported_names(tree):
            if name in CLOSED_MODULE_NAMES:
                rel = path.relative_to(REPO_ROOT)
                violations.append(f"{rel}:{lineno}: imports closed module '{name}'")
    assert not violations, "open code must never import closed modules:\n" + "\n".join(violations)


def test_import_guard_covers_expected_roots() -> None:
    scanned = {p.relative_to(REPO_ROOT).parts[0] for p in _iter_python_files()}
    for root in ("src", "tests"):
        assert root in scanned, f"scan root '{root}' produced no files; check SCAN_ROOTS"

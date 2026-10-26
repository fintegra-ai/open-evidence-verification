# SPDX-License-Identifier: Apache-2.0

"""Mechanical test proving protocol core independence from OEPT and EvidenceOS."""

import ast
from pathlib import Path

FORBIDDEN_MODULE_PREFIXES = (
    "oept",
    "EvidenceOS",
    "evidenceos",
    "evidenceos_core",
    "factoring",
    "finance",
)

OEV_SRC = Path(__file__).resolve().parents[1] / "src" / "oev"


def test_core_imports_independence():
    """Verify that every python file in src/oev except adapters/oept.py imports zero forbidden modules."""
    py_files = [p for p in OEV_SRC.rglob("*.py") if p.name != "oept.py"]
    assert len(py_files) >= 8, f"Expected at least 8 core python files, found {len(py_files)}"

    violations = []
    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for forbidden in FORBIDDEN_MODULE_PREFIXES:
                        if alias.name == forbidden or alias.name.startswith(f"{forbidden}."):
                            violations.append((py_file.name, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                for forbidden in FORBIDDEN_MODULE_PREFIXES:
                    if node.module == forbidden or node.module.startswith(f"{forbidden}."):
                        violations.append((py_file.name, node.lineno, node.module))

    assert not violations, f"Forbidden imports detected in protocol core: {violations}"

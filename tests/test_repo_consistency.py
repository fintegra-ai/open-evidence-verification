# SPDX-License-Identifier: Apache-2.0

"""Repository consistency guards: duplicate artifacts and documentation-adjacent invariants.

The JSON schemas live twice by design — once at the repository root (``schemas/``) for
humans and once inside the package (``src/oev/schemas/``) so wheels ship them. These
tests make sure the copies never drift apart.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG_SCHEMAS_DIR = REPO_ROOT / "src" / "oev" / "schemas"
REPO_SCHEMAS_DIR = REPO_ROOT / "schemas"


def test_package_and_repository_schema_copies_are_identical() -> None:
    repo_schemas = sorted(p.name for p in REPO_SCHEMAS_DIR.glob("*.json"))
    pkg_schemas = sorted(p.name for p in PKG_SCHEMAS_DIR.glob("*.json"))
    assert repo_schemas, "repository schemas/ directory is empty"
    assert repo_schemas == pkg_schemas, (
        "Schema file sets differ between schemas/ and src/oev/schemas/: "
        f"{set(repo_schemas) ^ set(pkg_schemas)}"
    )
    for name in repo_schemas:
        assert (REPO_SCHEMAS_DIR / name).read_bytes() == (PKG_SCHEMAS_DIR / name).read_bytes(), (
            f"Schema copies have drifted: {name}"
        )


def test_schema_loader_resolves_package_copy() -> None:
    from oev.schemas import get_schema_path

    for path in sorted(REPO_SCHEMAS_DIR.glob("*.json")):
        resolved = get_schema_path(path.name)
        assert resolved.is_file()
        assert resolved.name == path.name

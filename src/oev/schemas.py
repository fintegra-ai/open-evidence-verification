"""Schema loading and validation for OEVP artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

# Locations: try package data first, fallback to repository root
_PKG_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"
_REPO_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


class SchemaValidationError(ValueError):
    """Raised when an OEVP document violates its JSON Schema."""


def get_schema_path(schema_name: str) -> Path:
    """Resolve path to a JSON Schema file."""
    pkg_path = _PKG_SCHEMAS_DIR / schema_name
    if pkg_path.is_file():
        return pkg_path
    repo_path = _REPO_SCHEMAS_DIR / schema_name
    if repo_path.is_file():
        return repo_path
    raise FileNotFoundError(
        f"Schema {schema_name} not found in {_PKG_SCHEMAS_DIR} or {_REPO_SCHEMAS_DIR}"
    )


def load_schema(schema_name: str) -> dict[str, Any]:
    """Load schema JSON as dictionary."""
    path = get_schema_path(schema_name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def validate_document(document: dict[str, Any], schema_name: str) -> None:
    """Validate document dictionary against a named schema."""
    schema = load_schema(schema_name)
    try:
        validator_cls = jsonschema.validators.validator_for(schema)
        validator = validator_cls(schema)
        errors = list(validator.iter_errors(document))
        if errors:
            error_msgs = "; ".join(
                f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:5]
            )
            raise SchemaValidationError(f"Schema validation failed for {schema_name}: {error_msgs}")
    except SchemaValidationError:
        raise
    except Exception as exc:
        raise SchemaValidationError(f"Schema validation execution error: {exc}") from exc

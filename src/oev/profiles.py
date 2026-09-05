"""Verification Profile loading, validation, and content hashing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import canonicalize_json, safe_json_loads
from .hashing import sha256_bytes
from .models import VerificationProfile
from .schemas import validate_document

PROFILE_SCHEMA_NAME = "verification-profile.schema.json"


def compute_profile_digest(profile_data: dict[str, Any] | VerificationProfile) -> str:
    """Compute deterministic SHA-256 digest over JCS-canonicalized profile bytes."""
    d = profile_data.to_dict() if isinstance(profile_data, VerificationProfile) else profile_data
    canonical_bytes = canonicalize_json(d)
    return sha256_bytes(canonical_bytes)


def load_profile(source: str | Path | dict[str, Any]) -> VerificationProfile:
    """Load, validate, and instantiate a VerificationProfile from file path or dictionary."""
    if isinstance(source, (str, Path)):
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()
        data = safe_json_loads(content)
    elif isinstance(source, dict):
        data = source
    else:
        raise TypeError(f"Expected path or dict for profile, got {type(source).__name__}")

    validate_document(data, PROFILE_SCHEMA_NAME)
    return VerificationProfile.from_dict(data)

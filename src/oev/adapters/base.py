# SPDX-License-Identifier: Apache-2.0

"""Abstract base class and protocol for package format adapters in OEVP."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from oev.models import CheckResult, PackageReference, TrustInput, VerificationProfile


class OptionalDependencyMissingError(ImportError):
    """Raised when an adapter's underlying optional dependency is not installed."""


class PackageAdapter(ABC):
    """Abstract interface for evidence package format adapters.

    Adapters encapsulate format-specific parsing, archive safety, and check execution.
    The protocol core interacts with packages solely through this interface.
    """

    @property
    @abstractmethod
    def format_id(self) -> str:
        """Supported package format identifier (e.g. 'oept-bundle/0.1')."""

    @abstractmethod
    def can_handle(self, package_bytes: bytes) -> bool:
        """Return True if this adapter recognizes and can evaluate the package bytes."""

    @abstractmethod
    def inspect_package(self, package_bytes: bytes) -> PackageReference:
        """Extract metadata (format, digest, size, declared_id) without full verification."""

    @abstractmethod
    def supported_checks(self) -> set[str]:
        """Return set of check_ids that this adapter can evaluate."""

    @abstractmethod
    def evaluate(
        self,
        package_bytes: bytes,
        profile: VerificationProfile,
        trust_inputs: list[TrustInput],
        package_trusted_keys_pem: list[dict[str, Any]] | None = None,
    ) -> list[CheckResult]:
        """Execute atomic verification checks requested by the profile."""

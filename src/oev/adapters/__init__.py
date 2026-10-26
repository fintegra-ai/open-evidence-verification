# SPDX-License-Identifier: Apache-2.0

"""Package adapters package for OEVP."""

from __future__ import annotations

from oev.adapters.base import OptionalDependencyMissingError, PackageAdapter
from oev.adapters.oept import OEPTAdapter, is_oept_available

_ADAPTERS: list[PackageAdapter] = [
    OEPTAdapter(),
]


def get_adapter_for_package(package_bytes: bytes) -> PackageAdapter | None:
    """Find a registered adapter that can handle the provided package bytes."""
    for adapter in _ADAPTERS:
        if adapter.can_handle(package_bytes):
            return adapter
    return None


def get_adapter_for_format(format_id: str) -> PackageAdapter | None:
    """Find a registered adapter matching a format_id string."""
    for adapter in _ADAPTERS:
        if adapter.format_id == format_id:
            return adapter
    return None


__all__ = [
    "OEPTAdapter",
    "OptionalDependencyMissingError",
    "PackageAdapter",
    "get_adapter_for_format",
    "get_adapter_for_package",
    "is_oept_available",
]

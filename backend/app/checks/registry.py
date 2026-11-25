"""Check registry. Add a check by decorating one function with @register."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

PASS = "PASS"
FAIL = "FAIL"
CANNOT_SCAN = "CANNOT_SCAN"
STATUSES = (FAIL, CANNOT_SCAN, PASS)  # also the API sort order
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")  # highest to lowest


class CannotScan(Exception):
    """Raised by a check when a record cannot be evaluated."""


@dataclass(frozen=True)
class Context:
    """Everything a check may depend on. Never use the wall clock in checks."""

    snapshot_taken_at: datetime


CheckFn = Callable[[dict[str, Any], Context], tuple[str, str]]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    provider: str
    collection: str
    id_field: str
    fn: CheckFn

    def describe(self) -> dict[str, str]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "provider": self.provider,
            "collection": self.collection,
        }


REGISTRY: dict[str, Check] = {}


def register(
    *, id: str, title: str, severity: str, provider: str, collection: str, id_field: str
) -> Callable[[CheckFn], CheckFn]:
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")

    def decorator(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        REGISTRY[id] = Check(id, title, severity, provider, collection, id_field, fn)
        return fn

    return decorator

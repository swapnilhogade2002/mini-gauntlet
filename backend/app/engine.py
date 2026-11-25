"""Scanner engine: loads the snapshot and runs every registered check."""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks import REGISTRY, CannotScan, Check, Context
from .checks._util import safe
from .checks.registry import CANNOT_SCAN, FAIL, PASS

log = logging.getLogger("gauntlet.engine")


class InventoryError(Exception):
    """The snapshot cannot be read or has an invalid top-level shape."""


@dataclass
class Finding:
    check_id: str
    title: str
    provider: str
    account_id: str
    region: str | None
    resource_id: str | None
    status: str
    severity: str
    details: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Inventory:
    snapshot_taken_at: datetime
    accounts: list[dict[str, Any]]


def load_inventory(path: str | Path) -> Inventory:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        taken = datetime.fromisoformat(str(data["snapshot_taken_at"]).replace("Z", "+00:00"))
        accounts = data["accounts"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InventoryError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(accounts, list):
        raise InventoryError("'accounts' must be a list")
    if taken.tzinfo is None:
        taken = taken.replace(tzinfo=timezone.utc)
    valid = []
    for acc in accounts:
        if isinstance(acc, dict) and isinstance(acc.get("account_id"), str) and isinstance(acc.get("provider"), str):
            valid.append(acc)
        else:
            log.warning("skipping malformed account record: %s", safe(acc, 100))
    return Inventory(taken, valid)


def compute_score(passes: int, fails: int) -> float | None:
    """100 * PASS / (PASS + FAIL), rounded half-up to one decimal; None if nothing was scored."""
    total = passes + fails
    if total == 0:
        return None
    return ((2000 * passes + total) // (2 * total)) / 10


def _finding(check: Check, account: dict[str, Any], resource: Any, status: str, details: str) -> Finding:
    rid = region = None
    if isinstance(resource, dict):
        raw_id, raw_region = resource.get(check.id_field), resource.get("region")
        rid = safe(raw_id, 200) if raw_id not in (None, "") and not isinstance(raw_id, (dict, list)) else None
        region = safe(raw_region, 100) if isinstance(raw_region, str) else None
    return Finding(
        check.id, check.title, check.provider, account["account_id"], region, rid, status, check.severity, details
    )


def evaluate_resource(check: Check, account: dict[str, Any], resource: Any, ctx: Context) -> Finding:
    """Run one check on one record. Never raises: a bad record becomes CANNOT_SCAN."""
    try:
        if not isinstance(resource, dict):
            raise CannotScan("record is not an object")
        status, details = check.fn(resource, ctx)
    except CannotScan as exc:
        log.warning("%s on %s: cannot scan: %s", check.id, account["account_id"], exc)
        status, details = CANNOT_SCAN, str(exc)
    except Exception as exc:  # a buggy check must not stop the scan
        log.warning("%s on %s: unexpected %s: %s", check.id, account["account_id"], type(exc).__name__, exc)
        status, details = CANNOT_SCAN, f"Unexpected error while evaluating: {type(exc).__name__}"
    return _finding(check, account, resource, status, details)


def scan_account(account: dict[str, Any], ctx: Context, latency_scale: float = 1.0) -> list[Finding]:
    latency = account.get("simulated_latency_ms", 0)
    if isinstance(latency, (int, float)) and not isinstance(latency, bool) and latency > 0:
        time.sleep(latency / 1000 * latency_scale)  # stands in for cloud API calls
    elif latency:
        log.warning("account %s: invalid simulated_latency_ms", account["account_id"])
    errors: dict[str, Any] = account["errors"] if isinstance(account.get("errors"), dict) else {}
    resources: dict[str, Any] = account["resources"] if isinstance(account.get("resources"), dict) else {}
    findings: list[Finding] = []
    for check in REGISTRY.values():
        if check.provider != account["provider"]:
            continue
        if check.collection in errors:
            findings.append(
                _finding(
                    check,
                    account,
                    None,
                    CANNOT_SCAN,
                    f"Collection '{check.collection}' could not be read: {safe(errors[check.collection])}",
                )
            )
            continue
        items = resources.get(check.collection)
        if items is None:
            continue  # collection absent: no resources, no findings
        if not isinstance(items, list):
            log.warning("%s on %s: collection is not a list", check.id, account["account_id"])
            findings.append(
                _finding(
                    check, account, None, CANNOT_SCAN, f"Collection '{check.collection}' is malformed (not a list)"
                )
            )
            continue
        findings.extend(evaluate_resource(check, account, item, ctx) for item in items)
    return findings


def run_scan(
    inventory: Inventory, account_ids: list[str] | None = None, workers: int = 4, latency_scale: float = 1.0
) -> list[Finding]:
    accounts = [a for a in inventory.accounts if account_ids is None or a["account_id"] in account_ids]
    ctx = Context(snapshot_taken_at=inventory.snapshot_taken_at)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(lambda a: scan_account(a, ctx, latency_scale), accounts))
    return [f for batch in results for f in batch]


__all__ = [
    "Finding",
    "Inventory",
    "InventoryError",
    "load_inventory",
    "compute_score",
    "evaluate_resource",
    "scan_account",
    "run_scan",
    "PASS",
    "FAIL",
    "CANNOT_SCAN",
]

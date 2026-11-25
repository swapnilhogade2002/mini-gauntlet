"""Helpers shared by checks. Everything read from the snapshot is untrusted."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

from .registry import CANNOT_SCAN, FAIL, PASS, CannotScan

INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def safe(value: Any, limit: int = 60) -> str:
    """Make an untrusted value safe to embed in a message: no control chars, clipped."""
    text = _CONTROL.sub(" ", str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_port(value: Any) -> int:
    if isinstance(value, bool):
        raise CannotScan(f"port {safe(value)} is not a number")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise CannotScan(f"port {safe(value)!r} is not a number")
    if not 0 <= port <= 65535:
        raise CannotScan(f"port {port} is out of range 0-65535")
    return port


def parse_port_token(token: Any) -> tuple[int, int]:
    """'22', '3380-3400' or '*' -> inclusive (low, high)."""
    text = str(token).strip()
    if text == "*":
        return 0, 65535
    if "-" in text:
        lo_s, _, hi_s = text.partition("-")
        lo, hi = parse_port(lo_s), parse_port(hi_s)
    else:
        lo = hi = parse_port(text)
    if lo > hi:
        raise CannotScan(f"port range {safe(text)!r} is reversed")
    return lo, hi


def sensitive_hits(lo: int, hi: int) -> list[str]:
    return [f"{name} ({port})" for port, name in SENSITIVE_PORTS.items() if lo <= port <= hi]


def need_bool(resource: dict[str, Any], key: str) -> bool:
    value = resource.get(key)
    if not isinstance(value, bool):
        raise CannotScan(f"field '{key}' is missing or not a boolean (got {safe(value)!r})")
    return value


def need_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise CannotScan(f"{what} is missing or not a list")
    return value


def need_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CannotScan(f"{what} is not an object")
    return value


def collect(items: Iterable[Any], evaluate: Callable[[Any], str | None]) -> tuple[list[str], list[str]]:
    """Run evaluate on every item. Returns (fail messages, cannot-scan messages)."""
    fails: list[str] = []
    errors: list[str] = []
    for index, item in enumerate(items):
        try:
            message = evaluate(item)
        except CannotScan as exc:
            errors.append(f"item {index}: {exc}")
        else:
            if message:
                fails.append(message)
    return fails, errors


def verdict(fails: list[str], errors: list[str], ok: str) -> tuple[str, str]:
    """A definite FAIL wins; otherwise any unreadable item makes it CANNOT_SCAN."""
    if fails:
        return FAIL, "; ".join(fails)
    if errors:
        return CANNOT_SCAN, "; ".join(errors)
    return PASS, ok

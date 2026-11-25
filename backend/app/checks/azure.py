from __future__ import annotations

from typing import Any

from ._util import collect, need_bool, need_dict, need_list, parse_port_token, safe, sensitive_hits, verdict
from .registry import FAIL, PASS, CannotScan, Context, register

_INTERNET_SOURCES = {"*", "internet", "any", "0.0.0.0/0", "::/0"}


@register(
    id="AZ-STG-01",
    title="Storage account blocks public blob access",
    severity="HIGH",
    provider="azure",
    collection="storage_accounts",
    id_field="name",
)
def storage_blocks_public(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    if need_bool(res, "allow_blob_public_access"):
        return FAIL, "Storage account allows public blob access (allow_blob_public_access is true)"
    return PASS, "Public blob access is disabled"


def _nsg_rule(rule: Any) -> str | None:
    rule = need_dict(rule, "rule")
    if str(rule.get("direction", "")).lower() != "inbound":
        return None
    if str(rule.get("access", "")).lower() != "allow":
        return None
    source = str(rule.get("source", "")).strip()
    if source.lower() not in _INTERNET_SOURCES:
        return None
    protocol = str(rule.get("protocol", "")).lower()
    if protocol not in ("tcp", "*"):
        return None
    ports = rule.get("destination_ports")
    tokens = ports if isinstance(ports, list) else str(ports).split(",") if ports is not None else None
    if not tokens:
        raise CannotScan("destination_ports is missing")
    hits: list[str] = []
    for token in tokens:
        for hit in sensitive_hits(*parse_port_token(token)):
            if hit not in hits:
                hits.append(hit)
    if hits:
        return (
            f"rule '{safe(rule.get('name'))}' allows inbound {protocol} from {safe(source)} "
            f"to port(s) {safe(ports)}, exposing {', '.join(hits)}"
        )
    return None


@register(
    id="AZ-NSG-01",
    title="NSG doesn't expose SSH or RDP to the internet",
    severity="CRITICAL",
    provider="azure",
    collection="network_security_groups",
    id_field="name",
)
def nsg_no_ssh_rdp(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    rules = need_list(res.get("rules"), "rules")
    fails, errors = collect(rules, _nsg_rule)
    return verdict(fails, errors, "No inbound Allow rule exposes SSH (22) or RDP (3389) to the internet")

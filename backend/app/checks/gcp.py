from __future__ import annotations

from typing import Any

from ._util import INTERNET_CIDRS, collect, need_bool, need_dict, need_list, parse_port_token, safe, sensitive_hits
from .registry import FAIL, PASS, Context, register

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


@register(
    id="GCP-GCS-01",
    title="Bucket isn't public",
    severity="HIGH",
    provider="gcp",
    collection="gcs_buckets",
    id_field="name",
)
def gcs_not_public(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    bindings = need_list(res.get("iam_bindings"), "iam_bindings")
    public: list[str] = []
    for binding in bindings:
        binding = need_dict(binding, "iam binding")
        members = need_list(binding.get("members"), "members")
        found = sorted({m for m in members if isinstance(m, str) and m in _PUBLIC_MEMBERS})
        if found:
            public.append(f"{safe(binding.get('role'))} granted to {', '.join(found)}")
    if public:
        return FAIL, "Bucket is public: " + "; ".join(public)
    return PASS, "No IAM binding grants access to allUsers or allAuthenticatedUsers"


@register(
    id="GCP-GCS-02",
    title="Bucket uses uniform bucket-level access",
    severity="LOW",
    provider="gcp",
    collection="gcs_buckets",
    id_field="name",
)
def gcs_uniform_access(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    if need_bool(res, "uniform_bucket_level_access"):
        return PASS, "Uniform bucket-level access is enabled"
    return FAIL, "Uniform bucket-level access is disabled (object ACLs are in effect)"


def _allowed_entry(entry: Any) -> str | None:
    entry = need_dict(entry, "allowed entry")
    protocol = str(entry.get("IPProtocol", "")).lower()
    if protocol == "all":
        return "all protocols (exposes SSH (22), RDP (3389))"
    if protocol not in ("tcp", "6"):
        return None
    ports = entry.get("ports")
    if ports is None or ports == []:
        return "tcp on all ports (exposes SSH (22), RDP (3389))"
    hits: list[str] = []
    for token in need_list(ports, "ports"):
        for hit in sensitive_hits(*parse_port_token(token)):
            if hit not in hits:
                hits.append(hit)
    return f"tcp {', '.join(safe(p) for p in ports)} (exposes {', '.join(hits)})" if hits else None


@register(
    id="GCP-VPC-01",
    title="Firewall rule doesn't expose SSH or RDP to the internet",
    severity="CRITICAL",
    provider="gcp",
    collection="firewall_rules",
    id_field="name",
)
def firewall_no_ssh_rdp(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    ok = (PASS, "Rule does not expose SSH (22) or RDP (3389) to the internet")
    if str(res.get("direction", "")).upper() != "INGRESS":
        return ok
    if need_bool(res, "disabled") if "disabled" in res else False:
        return ok
    ranges = res.get("source_ranges") or []
    exposed = [r for r in need_list(ranges, "source_ranges") if isinstance(r, str) and r in INTERNET_CIDRS]
    if not exposed:
        return ok
    fails, errors = collect(need_list(res.get("allowed"), "allowed"), _allowed_entry)
    if fails:
        return FAIL, f"Enabled ingress rule from {', '.join(exposed)} allows " + "; ".join(fails)
    if errors:
        return "CANNOT_SCAN", "; ".join(errors)
    return ok

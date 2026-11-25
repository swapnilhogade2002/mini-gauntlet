from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ._util import (
    INTERNET_CIDRS,
    collect,
    need_bool,
    need_dict,
    need_list,
    parse_port,
    safe,
    sensitive_hits,
    verdict,
)
from .registry import FAIL, PASS, CannotScan, Context, register

_PAB_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")


@register(
    id="AWS-S3-01",
    title="S3 bucket blocks public access",
    severity="HIGH",
    provider="aws",
    collection="s3_buckets",
    id_field="name",
)
def s3_blocks_public_access(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    if "public_access_block" not in res:
        raise CannotScan("field 'public_access_block' is missing")
    block = res["public_access_block"]
    if block is None:
        # Assumption: no configuration means nothing blocks public access.
        return FAIL, "No public access block is configured on the bucket"
    block = need_dict(block, "public_access_block")
    off = []
    for flag in _PAB_FLAGS:
        value = need_bool(block, flag)
        if not value:
            off.append(flag)
    if off:
        return FAIL, "Public access block setting(s) disabled: " + ", ".join(off)
    return PASS, "All four public access block settings are enabled"


def _sg_rule(rule: Any) -> str | None:
    rule = need_dict(rule, "ingress rule")
    cidrs = need_list(rule.get("cidrs"), "cidrs")
    exposed = [c for c in cidrs if isinstance(c, str) and c in INTERNET_CIDRS]
    if not exposed:
        return None
    source = ", ".join(exposed)
    protocol = str(rule.get("protocol", "")).lower()
    if protocol in ("-1", "all"):
        return f"rule allows all protocols and ports from {source} (exposes SSH (22), RDP (3389))"
    if protocol not in ("tcp", "6"):
        return None
    lo, hi = parse_port(rule.get("from_port")), parse_port(rule.get("to_port"))
    if lo > hi:
        raise CannotScan(f"port range {lo}-{hi} is reversed")
    hits = sensitive_hits(lo, hi)
    if hits:
        label = str(lo) if lo == hi else f"{lo}-{hi}"
        return f"tcp {label} open to {source} exposes {', '.join(hits)}"
    return None


@register(
    id="AWS-EC2-01",
    title="Security group doesn't expose SSH or RDP to the internet",
    severity="CRITICAL",
    provider="aws",
    collection="security_groups",
    id_field="group_id",
)
def sg_no_ssh_rdp(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    rules = need_list(res.get("ingress"), "ingress")
    fails, errors = collect(rules, _sg_rule)
    return verdict(fails, errors, "No ingress rule exposes SSH (22) or RDP (3389) to the internet")


@register(
    id="AWS-IAM-01",
    title="Console users have MFA",
    severity="HIGH",
    provider="aws",
    collection="iam_users",
    id_field="user_name",
)
def iam_console_mfa(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    if not need_bool(res, "console_access"):
        return PASS, "User has no console access, so MFA is not required"
    if need_bool(res, "mfa_enabled"):
        return PASS, "Console user has MFA enabled"
    return FAIL, "User has console access but MFA is not enabled"


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CannotScan(f"timestamp {safe(value)!r} is not a string")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise CannotScan(f"timestamp {safe(value)!r} is not ISO 8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


MAX_KEY_AGE = timedelta(days=90)


@register(
    id="AWS-IAM-02",
    title="No active access key is older than 90 days",
    severity="MEDIUM",
    provider="aws",
    collection="iam_users",
    id_field="user_name",
)
def iam_key_age(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    keys = need_list(res.get("access_keys"), "access_keys")

    def evaluate(key: Any) -> str | None:
        key = need_dict(key, "access key")
        if str(key.get("status", "")).lower() != "active":
            return None
        age = ctx.snapshot_taken_at - _parse_time(key.get("created_at"))
        if age > MAX_KEY_AGE:  # exactly 90 days is still compliant
            return f"Access key {safe(key.get('key_id'))} is {age.days} days old (limit is 90)"
        return None

    fails, errors = collect(keys, evaluate)
    return verdict(fails, errors, "No active access key is older than 90 days")


@register(
    id="AWS-RDS-01",
    title="RDS instance isn't publicly accessible",
    severity="HIGH",
    provider="aws",
    collection="rds_instances",
    id_field="db_instance_id",
)
def rds_not_public(res: dict[str, Any], ctx: Context) -> tuple[str, str]:
    if need_bool(res, "publicly_accessible"):
        return FAIL, "RDS instance is publicly accessible"
    return PASS, "RDS instance is not publicly accessible"

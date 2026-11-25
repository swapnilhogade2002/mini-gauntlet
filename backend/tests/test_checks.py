from datetime import datetime, timezone

import pytest

from app.checks import REGISTRY, Context
from app.engine import evaluate_resource

CTX = Context(snapshot_taken_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
ACC = {"account_id": "acc", "provider": "x"}


def run(check_id, resource):
    f = evaluate_resource(REGISTRY[check_id], ACC, resource, CTX)
    return f.status, f.details


def test_catalog_has_ten_checks():
    assert sorted(REGISTRY) == sorted(
        [
            "AWS-S3-01",
            "AWS-EC2-01",
            "AWS-IAM-01",
            "AWS-IAM-02",
            "AWS-RDS-01",
            "AZ-STG-01",
            "AZ-NSG-01",
            "GCP-GCS-01",
            "GCP-GCS-02",
            "GCP-VPC-01",
        ]
    )
    assert REGISTRY["AWS-EC2-01"].severity == "CRITICAL" and REGISTRY["GCP-GCS-02"].severity == "LOW"


# ---- AWS-S3-01 ------------------------------------------------------------------------------
ALL_ON = dict.fromkeys(
    ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"], True
)


@pytest.mark.parametrize(
    "block,expected",
    [
        (ALL_ON, "PASS"),
        ({**ALL_ON, "block_public_policy": False}, "FAIL"),
        (None, "FAIL"),
        ({**ALL_ON, "block_public_acls": "yes"}, "CANNOT_SCAN"),
        ("nonsense", "CANNOT_SCAN"),
    ],
)
def test_s3(block, expected):
    assert run("AWS-S3-01", {"name": "b", "public_access_block": block})[0] == expected


def test_s3_missing_field_cannot_scan():
    assert run("AWS-S3-01", {"name": "b"})[0] == "CANNOT_SCAN"


def test_s3_fail_names_the_setting():
    assert (
        "block_public_policy" in run("AWS-S3-01", {"public_access_block": {**ALL_ON, "block_public_policy": False}})[1]
    )


# ---- AWS-EC2-01 -----------------------------------------------------------------------------
def sg(*rules):
    return {"group_id": "sg-1", "ingress": list(rules)}


def rule(lo, hi, cidrs, proto="tcp"):
    return {"protocol": proto, "from_port": lo, "to_port": hi, "cidrs": cidrs}


@pytest.mark.parametrize(
    "r,expected",
    [
        (rule(22, 22, ["0.0.0.0/0"]), "FAIL"),
        (rule(3389, 3389, ["0.0.0.0/0"]), "FAIL"),
        (rule(22, 22, ["::/0"]), "FAIL"),  # IPv6 internet
        (rule(3000, 3500, ["0.0.0.0/0"]), "FAIL"),  # range containing 3389
        (rule(1, 65535, ["0.0.0.0/0"]), "FAIL"),
        (rule(None, None, ["0.0.0.0/0"], "-1"), "FAIL"),  # all traffic
        (rule(20, 21, ["0.0.0.0/0"]), "PASS"),  # range just below 22
        (rule(23, 3388, ["0.0.0.0/0"]), "PASS"),  # range between 22 and 3389
        (rule(443, 443, ["0.0.0.0/0", "::/0"]), "PASS"),
        (rule(22, 22, ["203.0.113.0/24"]), "PASS"),  # not the internet
        (rule(22, 22, ["0.0.0.0/0"], "udp"), "PASS"),
        (rule("twenty-two", 22, ["0.0.0.0/0"]), "CANNOT_SCAN"),
        (rule(22, True, ["0.0.0.0/0"]), "CANNOT_SCAN"),
        (rule(100, 50, ["0.0.0.0/0"]), "CANNOT_SCAN"),
        ({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": "0.0.0.0/0"}, "CANNOT_SCAN"),
    ],
)
def test_sg(r, expected):
    assert run("AWS-EC2-01", sg(r))[0] == expected


def test_sg_no_rules_passes_and_missing_ingress_cannot_scan():
    assert run("AWS-EC2-01", sg())[0] == "PASS"
    assert run("AWS-EC2-01", {"group_id": "x"})[0] == "CANNOT_SCAN"


def test_sg_fail_beats_cannot_scan_and_names_port_and_source():
    status, details = run("AWS-EC2-01", sg(rule("bad", 1, ["0.0.0.0/0"]), rule(22, 22, ["::/0"])))
    assert status == "FAIL" and "22" in details and "::/0" in details


# ---- AWS-IAM-01 -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "console,mfa,expected",
    [
        (True, True, "PASS"),
        (True, False, "FAIL"),
        (False, False, "PASS"),
        ("yes", True, "CANNOT_SCAN"),
        (True, None, "CANNOT_SCAN"),
    ],
)
def test_iam_mfa(console, mfa, expected):
    assert run("AWS-IAM-01", {"user_name": "u", "console_access": console, "mfa_enabled": mfa})[0] == expected


# ---- AWS-IAM-02 (snapshot is 2026-10-01; 90 days before is 2026-07-03) --------------------------
def user(*keys):
    return {"user_name": "u", "access_keys": [{"key_id": "k", **k} for k in keys]}


@pytest.mark.parametrize(
    "key,expected",
    [
        ({"status": "Active", "created_at": "2026-07-03T00:00:00Z"}, "PASS"),  # exactly 90 days
        ({"status": "Active", "created_at": "2026-07-02T00:00:00Z"}, "FAIL"),  # 91 days
        ({"status": "Active", "created_at": "2026-07-03T00:00:01Z"}, "PASS"),
        ({"status": "Inactive", "created_at": "2020-01-01T00:00:00Z"}, "PASS"),  # inactive ignored
        ({"status": "Active", "created_at": "2030-01-01T00:00:00Z"}, "PASS"),  # future date
        ({"status": "Active", "created_at": "not a date"}, "CANNOT_SCAN"),
        ({"status": "Active"}, "CANNOT_SCAN"),
    ],
)
def test_key_age(key, expected):
    assert run("AWS-IAM-02", user(key))[0] == expected


def test_key_age_no_keys_and_malformed():
    assert run("AWS-IAM-02", user())[0] == "PASS"
    assert run("AWS-IAM-02", {"user_name": "u", "access_keys": None})[0] == "CANNOT_SCAN"


def test_key_age_details_mention_age():
    assert "91 days" in run("AWS-IAM-02", user({"status": "Active", "created_at": "2026-07-02T00:00:00Z"}))[1]


# ---- AWS-RDS-01 / AZ-STG-01 / GCP-GCS-02 (simple booleans) --------------------------------------
@pytest.mark.parametrize(
    "check,field", [("AWS-RDS-01", "publicly_accessible"), ("AZ-STG-01", "allow_blob_public_access")]
)
def test_bool_fail_checks(check, field):
    assert run(check, {field: False})[0] == "PASS"
    assert run(check, {field: True})[0] == "FAIL"
    assert run(check, {field: "true"})[0] == "CANNOT_SCAN"
    assert run(check, {})[0] == "CANNOT_SCAN"


def test_gcs_uniform():
    assert run("GCP-GCS-02", {"uniform_bucket_level_access": True})[0] == "PASS"
    assert run("GCP-GCS-02", {"uniform_bucket_level_access": False})[0] == "FAIL"
    assert run("GCP-GCS-02", {})[0] == "CANNOT_SCAN"


# ---- AZ-NSG-01 --------------------------------------------------------------------------------
def nsg(**kw):
    base = {
        "name": "r",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "source": "Internet",
        "destination_ports": "22",
    }
    return {"name": "n", "rules": [{**base, **kw}]}


@pytest.mark.parametrize(
    "kw,expected",
    [
        ({}, "FAIL"),
        ({"source": "*"}, "FAIL"),
        ({"source": "0.0.0.0/0", "destination_ports": "3380-3400", "protocol": "*"}, "FAIL"),
        ({"destination_ports": "*"}, "FAIL"),
        ({"destination_ports": "80,443,3389"}, "FAIL"),
        ({"access": "Deny"}, "PASS"),
        ({"direction": "Outbound"}, "PASS"),
        ({"source": "10.0.0.0/8"}, "PASS"),
        ({"protocol": "Udp"}, "PASS"),
        ({"destination_ports": "443"}, "PASS"),
        ({"destination_ports": "23-3388"}, "PASS"),
        ({"destination_ports": "ssh"}, "CANNOT_SCAN"),
        ({"destination_ports": None}, "CANNOT_SCAN"),
    ],
)
def test_nsg(kw, expected):
    assert run("AZ-NSG-01", nsg(**kw))[0] == expected


def test_nsg_rules_not_a_list():
    assert run("AZ-NSG-01", {"name": "n", "rules": "x"})[0] == "CANNOT_SCAN"


# ---- GCP-GCS-01 -------------------------------------------------------------------------------
def bucket(*members):
    return {"name": "b", "iam_bindings": [{"role": "roles/x", "members": list(members)}]}


def test_gcs_public():
    assert run("GCP-GCS-01", bucket("allUsers"))[0] == "FAIL"
    assert run("GCP-GCS-01", bucket("user:a@b.c", "allAuthenticatedUsers"))[0] == "FAIL"
    assert run("GCP-GCS-01", bucket("group:x@y.z"))[0] == "PASS"
    assert run("GCP-GCS-01", {"name": "b", "iam_bindings": []})[0] == "PASS"
    assert run("GCP-GCS-01", {"name": "b", "iam_bindings": "x"})[0] == "CANNOT_SCAN"


# ---- GCP-VPC-01 -------------------------------------------------------------------------------
def fw(**kw):
    base = {
        "name": "f",
        "direction": "INGRESS",
        "disabled": False,
        "source_ranges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    }
    return {**base, **kw}


@pytest.mark.parametrize(
    "kw,expected",
    [
        ({}, "FAIL"),
        ({"allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}]}, "FAIL"),
        ({"allowed": [{"IPProtocol": "all"}]}, "FAIL"),
        ({"allowed": [{"IPProtocol": "tcp"}]}, "FAIL"),  # no ports means all ports
        ({"allowed": [{"IPProtocol": "tcp", "ports": ["1000-4000"]}]}, "FAIL"),
        ({"source_ranges": ["::/0"]}, "FAIL"),
        ({"disabled": True, "allowed": [{"IPProtocol": "all"}]}, "PASS"),
        ({"direction": "EGRESS"}, "PASS"),
        ({"source_ranges": ["35.235.240.0/20"]}, "PASS"),
        ({"allowed": [{"IPProtocol": "tcp", "ports": ["8000-9000"]}]}, "PASS"),
        ({"allowed": [{"IPProtocol": "udp", "ports": ["22"]}]}, "PASS"),
        ({"allowed": [{"IPProtocol": "tcp", "ports": ["abc"]}]}, "CANNOT_SCAN"),
        ({"disabled": "no"}, "CANNOT_SCAN"),
        ({"allowed": None}, "CANNOT_SCAN"),
    ],
)
def test_firewall(kw, expected):
    assert run("GCP-VPC-01", fw(**kw))[0] == expected


def test_untrusted_strings_are_clipped_and_cleaned():
    status, details = run("AZ-NSG-01", nsg(name="x" * 500 + "\n\x00"))
    assert status == "FAIL" and len(details) < 400 and "\n" not in details

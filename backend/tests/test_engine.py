import time

import pytest

from app.checks import REGISTRY, Context
from app.checks.registry import register
from app.engine import InventoryError, compute_score, load_inventory, run_scan, scan_account
from tests.conftest import INVENTORY, write_inventory


def test_score_rounding_and_na():
    assert compute_score(27, 18) == 60.0
    assert compute_score(2, 1) == 66.7
    assert compute_score(1, 7) == 12.5
    assert compute_score(0, 0) is None
    assert compute_score(0, 3) == 0.0


def test_full_snapshot_counts():
    findings = run_scan(load_inventory(INVENTORY), latency_scale=0)
    counts = {s: sum(f.status == s for f in findings) for s in ("PASS", "FAIL", "CANNOT_SCAN")}
    assert counts == {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}


def test_scans_are_deterministic():
    inv = load_inventory(INVENTORY)
    a = [f.as_dict() for f in run_scan(inv, latency_scale=0)]
    b = [f.as_dict() for f in run_scan(inv, latency_scale=0)]
    assert a == b


def test_errored_collection_gives_one_finding_per_check_without_resource_id():
    inv = load_inventory(INVENTORY)
    dev = next(a for a in inv.accounts if a["account_id"] == "210987654321")
    found = scan_account(dev, Context(inv.snapshot_taken_at), 0)
    errs = [f for f in found if f.resource_id is None]
    assert sorted(f.check_id for f in errs) == ["AWS-IAM-01", "AWS-IAM-02", "AWS-RDS-01"]
    assert {f.details.split(": ")[-1] for f in errs} == {"AccessDenied", "UnauthorizedOperation"}


def test_missing_collection_yields_no_findings(tmp_path):
    path = write_inventory(
        tmp_path / "i.json",
        [{"provider": "gcp", "account_id": "g", "name": "g", "simulated_latency_ms": 0, "errors": {}, "resources": {}}],
    )
    assert run_scan(load_inventory(path), latency_scale=0) == []


def test_bad_records_never_stop_the_scan(tmp_path):
    path = write_inventory(
        tmp_path / "i.json",
        [
            {
                "provider": "aws",
                "account_id": "a",
                "name": "a",
                "simulated_latency_ms": 0,
                "errors": {},
                "resources": {
                    "rds_instances": [None, 42, {"db_instance_id": "ok", "publicly_accessible": False}],
                    "s3_buckets": "not a list",
                },
            }
        ],
    )
    findings = run_scan(load_inventory(path), latency_scale=0)
    statuses = sorted((f.check_id, f.status) for f in findings)
    assert statuses == [
        ("AWS-RDS-01", "CANNOT_SCAN"),
        ("AWS-RDS-01", "CANNOT_SCAN"),
        ("AWS-RDS-01", "PASS"),
        ("AWS-S3-01", "CANNOT_SCAN"),
    ]


def test_crashing_check_becomes_cannot_scan_and_others_continue():
    @register(id="TEST-BOOM", title="boom", severity="LOW", provider="gcp", collection="gcs_buckets", id_field="name")
    def boom(res, ctx):
        raise RuntimeError("bug")

    try:
        findings = run_scan(load_inventory(INVENTORY), ["example-corp-gcp"], latency_scale=0)
        boom_findings = [f for f in findings if f.check_id == "TEST-BOOM"]
        assert len(boom_findings) == 3 and all(f.status == "CANNOT_SCAN" for f in boom_findings)
        assert any(f.check_id == "GCP-GCS-01" and f.status == "FAIL" for f in findings)
    finally:
        del REGISTRY["TEST-BOOM"]  # adding a check needed no edits elsewhere; this cleans up the test


def test_duplicate_check_id_rejected():
    with pytest.raises(ValueError):
        register(id="AWS-S3-01", title="x", severity="LOW", provider="aws", collection="c", id_field="i")(
            lambda r, c: ("PASS", "")
        )


def _timed_inventory(tmp_path):
    accounts = [
        {
            "provider": "gcp",
            "account_id": f"g{i}",
            "name": "g",
            "simulated_latency_ms": 300,
            "errors": {},
            "resources": {},
        }
        for i in range(4)
    ]
    return load_inventory(write_inventory(tmp_path / "i.json", accounts))


def test_accounts_scan_concurrently(tmp_path):
    inv = _timed_inventory(tmp_path)
    start = time.perf_counter()
    run_scan(inv, workers=4)
    parallel = time.perf_counter() - start
    start = time.perf_counter()
    run_scan(inv, workers=1)
    serial = time.perf_counter() - start
    assert parallel < 0.8 and serial >= 1.1


def test_unreadable_inventory(tmp_path):
    with pytest.raises(InventoryError):
        load_inventory(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(InventoryError):
        load_inventory(bad)

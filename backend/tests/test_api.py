from tests.conftest import INVENTORY, wait_done, write_inventory

DEV = "210987654321"


def test_health_and_checks(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    checks = client.get("/api/checks").json()
    assert len(checks) == 10 and {"id", "title", "severity", "provider", "collection"} <= set(checks[0])


def test_start_scan_returns_202_running_then_completes(client):
    resp = client.post("/api/scans")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "RUNNING" and len(body["account_ids"]) == 4
    done = wait_done(client, body["id"])
    assert done["status"] == "COMPLETED" and done["finished_at"]


def test_scan_summary(full_scan):
    assert full_scan["counts"] == {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}
    assert full_scan["score"] == 60.0
    assert full_scan["fail_by_severity"] == {"CRITICAL": 7, "HIGH": 8, "MEDIUM": 2, "LOW": 1}
    scores = {a["account_id"]: a["score"] for a in full_scan["accounts"]}
    assert scores[DEV] == 66.7 and len(scores) == 4


def test_list_scans_newest_first(client):
    first = wait_done(client, client.post("/api/scans").json()["id"])
    second = wait_done(client, client.post("/api/scans", json={"account_ids": [DEV]}).json()["id"])
    listing = client.get("/api/scans").json()
    assert [s["id"] for s in listing] == [second["id"], first["id"]]
    assert listing[0]["account_ids"] == [DEV] and listing[0]["counts"]["CANNOT_SCAN"] == 4


def test_unknown_scan_is_404(client):
    assert client.get("/api/scans/nope").status_code == 404
    assert client.get("/api/scans/nope/findings").status_code == 404


def test_bad_start_requests_are_422(client):
    assert client.post("/api/scans", json={"account_ids": []}).status_code == 422
    assert client.post("/api/scans", json={"account_ids": ["nope"]}).status_code == 422
    assert client.post("/api/scans", json={"account_ids": "x"}).status_code == 422
    assert client.get("/api/scans").json() == []  # nothing was created


def test_findings_default_order_and_shape(client, full_scan):
    page = client.get(f"/api/scans/{full_scan['id']}/findings").json()
    assert page["total"] == 49 and page["page"] == 1 and page["page_size"] == 25 and len(page["items"]) == 25
    assert {
        "id",
        "scan_id",
        "check_id",
        "title",
        "provider",
        "account_id",
        "region",
        "resource_id",
        "status",
        "severity",
        "details",
    } == set(page["items"][0])
    rank = {"FAIL": 0, "CANNOT_SCAN": 1, "PASS": 2}
    sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items = client.get(f"/api/scans/{full_scan['id']}/findings", params={"page_size": 100}).json()["items"]
    keys = [(rank[i["status"]], sev[i["severity"]], i["check_id"], i["resource_id"] or "") for i in items]
    assert keys == sorted(keys)
    assert items[0]["status"] == "FAIL" and items[0]["severity"] == "CRITICAL"


def test_pagination(client, full_scan):
    url = f"/api/scans/{full_scan['id']}/findings"
    p1 = client.get(url, params={"page_size": 20}).json()
    p3 = client.get(url, params={"page_size": 20, "page": 3}).json()
    p4 = client.get(url, params={"page_size": 20, "page": 4}).json()
    assert len(p1["items"]) == 20 and len(p3["items"]) == 9 and p4["items"] == [] and p4["total"] == 49
    ids = {i["id"] for i in p1["items"]} & {i["id"] for i in p3["items"]}
    assert not ids
    assert client.get(url, params={"page_size": 101}).status_code == 422
    assert client.get(url, params={"page": 0}).status_code == 422


def test_filters_are_case_insensitive_and_combine(client, full_scan):
    url = f"/api/scans/{full_scan['id']}/findings"

    def total(**params):
        return client.get(url, params=params).json()["total"]

    assert total(status="fail") == 18 and total(status="FAIL") == 18
    assert (
        total(status="cannot_scan") == 4
        and total(status="fail", severity="critical") == total(status="FAIL", severity="CRITICAL") == 7
    )
    assert total(provider="AWS") == 31 and total(provider="gcp") == 11
    assert total(account_id=DEV) == 7 and total(check_id="aws-s3-01") == 5
    assert total(status="fail", provider="aws", severity="high") == total(
        status="FAIL", provider="aws", severity="HIGH"
    )
    assert total(status="bogus") == 0


def test_failed_scan_when_snapshot_unreadable(make_client, tmp_path):
    client = make_client(inventory=tmp_path / "missing.json")
    resp = client.post("/api/scans")
    assert resp.status_code == 202
    done = wait_done(client, resp.json()["id"])
    assert done["status"] == "FAILED" and "cannot read inventory" in done["error"]


def test_na_score_when_nothing_scored(make_client, tmp_path):
    inv = write_inventory(
        tmp_path / "i.json",
        [{"provider": "aws", "account_id": "a", "name": "a", "simulated_latency_ms": 0, "errors": {}, "resources": {}}],
    )
    client = make_client(inventory=inv)
    done = wait_done(client, client.post("/api/scans").json()["id"])
    assert done["status"] == "COMPLETED" and done["score"] is None


def test_data_survives_restart(make_client, tmp_path):
    db = tmp_path / "persist.db"
    first = make_client(db=db)
    scan = wait_done(first, first.post("/api/scans").json()["id"])
    second = make_client(db=db)
    assert second.get(f"/api/scans/{scan['id']}").json()["counts"] == scan["counts"]
    assert second.get(f"/api/scans/{scan['id']}/findings").json()["total"] == 49


def test_scan_left_running_is_failed_on_restart(make_client, tmp_path):
    from app.db import Database

    db = tmp_path / "crash.db"
    database = Database(str(db))
    database.init()
    scan_id = database.create_scan([])
    client = make_client(db=db)
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "FAILED"


def test_inventory_file_is_the_graded_one():
    assert INVENTORY.exists()

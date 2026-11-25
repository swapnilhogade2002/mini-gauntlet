import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

INVENTORY = Path(__file__).resolve().parents[2] / "data" / "inventory.json"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    def factory(inventory: Path = INVENTORY, db: Path | None = None) -> TestClient:
        monkeypatch.setenv("INVENTORY_PATH", str(inventory))
        monkeypatch.setenv("DATABASE_PATH", str(db or tmp_path / "test.db"))
        monkeypatch.setenv("SCAN_LATENCY_SCALE", "0")
        return TestClient(create_app())

    return factory


@pytest.fixture
def client(make_client):
    return make_client()


def wait_done(client: TestClient, scan_id: str, timeout: float = 10) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] != "RUNNING":
            return scan
        time.sleep(0.02)
    raise AssertionError("scan did not finish")


@pytest.fixture
def full_scan(client):
    resp = client.post("/api/scans")
    assert resp.status_code == 202
    return wait_done(client, resp.json()["id"])


def write_inventory(path: Path, accounts: list, taken: str = "2026-10-01T00:00:00Z") -> Path:
    path.write_text(json.dumps({"snapshot_taken_at": taken, "accounts": accounts}))
    return path

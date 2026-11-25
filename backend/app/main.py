"""REST API. Run with: uvicorn app.main:create_app --factory"""

from __future__ import annotations

import logging
import os
import threading
from typing import Annotated, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from .checks import REGISTRY
from .db import Database
from .engine import InventoryError, load_inventory, run_scan

log = logging.getLogger("gauntlet.api")


class ScanRequest(BaseModel):
    account_ids: Optional[list[str]] = None


def create_app() -> FastAPI:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    inventory_path = os.getenv("INVENTORY_PATH", "data/inventory.json")
    workers = int(os.getenv("SCAN_WORKERS", "4"))
    scale = float(os.getenv("SCAN_LATENCY_SCALE", "1"))  # tests set 0 to skip the simulated latency
    db = Database(os.getenv("DATABASE_PATH", "gauntlet.db"))
    db.init()
    app = FastAPI(title="Mini Gauntlet")

    def worker(scan_id: str, account_ids: list[str] | None) -> None:
        try:
            inventory = load_inventory(inventory_path)
            findings = run_scan(inventory, account_ids, workers, scale)
            scanned = [
                {"account_id": a["account_id"], "name": str(a.get("name", "")), "provider": a["provider"]}
                for a in inventory.accounts
                if account_ids is None or a["account_id"] in account_ids
            ]
            db.complete_scan(scan_id, findings, scanned)
        except Exception as exc:
            log.exception("scan %s failed", scan_id)
            db.fail_scan(scan_id, f"{type(exc).__name__}: {exc}"[:500])

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/checks")
    def checks() -> list[dict[str, str]]:
        return [c.describe() for c in REGISTRY.values()]

    @app.post("/api/scans", status_code=202)
    def start_scan(body: ScanRequest | None = None) -> dict:
        requested = body.account_ids if body else None
        if requested is not None and not requested:
            raise HTTPException(422, "account_ids must not be empty; omit it to scan every account")
        requested = list(dict.fromkeys(requested)) if requested else None
        accounts = [{"account_id": a, "name": "", "provider": ""} for a in requested or []]
        try:
            inventory = load_inventory(inventory_path)
        except InventoryError:
            inventory = None  # the background scan will fail and record why
        if inventory is not None:
            known = {a["account_id"]: a for a in inventory.accounts}
            unknown = [a for a in requested or [] if a not in known]
            if unknown:
                raise HTTPException(422, f"unknown account_ids: {', '.join(unknown)}")
            accounts = [
                {"account_id": a["account_id"], "name": str(a.get("name", "")), "provider": a["provider"]}
                for a in inventory.accounts
                if requested is None or a["account_id"] in requested
            ]
        scan_id = db.create_scan(accounts)
        threading.Thread(target=worker, args=(scan_id, requested), daemon=True).start()
        scan = db.get_scan(scan_id)
        assert scan is not None
        scan["status"] = "RUNNING"  # the worker may already have finished; the response reports the start
        return scan

    @app.get("/api/scans")
    def list_scans() -> list[dict]:
        return db.list_scans()

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, "scan not found")
        return scan

    @app.get("/api/scans/{scan_id}/findings")
    def get_findings(
        scan_id: str,
        status: str | None = None,
        severity: str | None = None,
        provider: str | None = None,
        account_id: str | None = None,
        check_id: str | None = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> dict:
        if db.get_scan(scan_id) is None:
            raise HTTPException(404, "scan not found")
        filters = {
            "status": status,
            "severity": severity,
            "provider": provider,
            "account_id": account_id,
            "check_id": check_id,
        }
        return db.list_findings(scan_id, filters, page, page_size)

    return app

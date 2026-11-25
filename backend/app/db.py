"""SQLite persistence for scans and findings (stdlib sqlite3, one connection per call)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from .checks.registry import CANNOT_SCAN, FAIL, PASS, SEVERITIES
from .engine import Finding, compute_score

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
  accounts_json TEXT NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(id),
  check_id TEXT NOT NULL, title TEXT NOT NULL, provider TEXT NOT NULL, account_id TEXT NOT NULL,
  region TEXT, resource_id TEXT, status TEXT NOT NULL, severity TEXT NOT NULL, details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""
_ORDER = """ORDER BY CASE status WHEN 'FAIL' THEN 0 WHEN 'CANNOT_SCAN' THEN 1 ELSE 2 END,
  CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
  check_id, COALESCE(resource_id, ''), id"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _empty_counts() -> dict[str, int]:
    return {PASS: 0, FAIL: 0, CANNOT_SCAN: 0}


class Database:
    def __init__(self, path: str) -> None:
        self.path = path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with closing(self._conn()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            # A scan left RUNNING by a crash or restart can never finish.
            conn.execute(
                "UPDATE scans SET status='FAILED', finished_at=?, error='Interrupted by restart' "
                "WHERE status='RUNNING'",
                (now(),),
            )
            conn.commit()

    def create_scan(self, accounts: list[dict[str, str]]) -> str:
        scan_id = uuid.uuid4().hex
        with closing(self._conn()) as conn:
            conn.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?,?)", (scan_id, "RUNNING", now(), None, json.dumps(accounts), None)
            )
            conn.commit()
        return scan_id

    def complete_scan(self, scan_id: str, findings: list[Finding], accounts: list[dict[str, str]]) -> None:
        with closing(self._conn()) as conn:
            conn.executemany(
                "INSERT INTO findings (scan_id, check_id, title, provider, account_id, region, resource_id,"
                " status, severity, details) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id,
                        f.check_id,
                        f.title,
                        f.provider,
                        f.account_id,
                        f.region,
                        f.resource_id,
                        f.status,
                        f.severity,
                        f.details,
                    )
                    for f in findings
                ],
            )
            conn.execute(
                "UPDATE scans SET status='COMPLETED', finished_at=?, accounts_json=? WHERE id=?",
                (now(), json.dumps(accounts), scan_id),
            )
            conn.commit()

    def fail_scan(self, scan_id: str, error: str) -> None:
        with closing(self._conn()) as conn:
            conn.execute("UPDATE scans SET status='FAILED', finished_at=?, error=? WHERE id=?", (now(), error, scan_id))
            conn.commit()

    # ---- reads -------------------------------------------------------------------------------
    def _counts(self, conn: sqlite3.Connection, scan_id: str) -> dict[str, dict[str, Any]]:
        """Counts per account: {account_id: {'counts': {...}, 'fail_by_severity': {...}}}"""
        out: dict[str, dict[str, Any]] = {}
        rows = conn.execute(
            "SELECT account_id, status, severity, COUNT(*) n FROM findings " "WHERE scan_id=? GROUP BY 1,2,3",
            (scan_id,),
        )
        for r in rows:
            entry = out.setdefault(
                r["account_id"], {"counts": _empty_counts(), "fail_by_severity": {s: 0 for s in SEVERITIES}}
            )
            entry["counts"][r["status"]] += r["n"]
            if r["status"] == FAIL:
                entry["fail_by_severity"][r["severity"]] += r["n"]
        return out

    def _summary(self, conn: sqlite3.Connection, row: sqlite3.Row, detail: bool) -> dict[str, Any]:
        accounts = json.loads(row["accounts_json"])
        per = self._counts(conn, row["id"])
        counts, by_sev = _empty_counts(), {s: 0 for s in SEVERITIES}
        for entry in per.values():
            for k, v in entry["counts"].items():
                counts[k] += v
            for k, v in entry["fail_by_severity"].items():
                by_sev[k] += v
        result: dict[str, Any] = {
            "id": row["id"],
            "status": row["status"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "account_ids": [a["account_id"] for a in accounts],
            "error": row["error"],
            "counts": counts,
            "score": compute_score(counts[PASS], counts[FAIL]),
        }
        if detail:
            result["fail_by_severity"] = by_sev
            result["accounts"] = []
            for a in accounts:
                e = per.get(a["account_id"], {"counts": _empty_counts()})
                result["accounts"].append(
                    {**a, "counts": e["counts"], "score": compute_score(e["counts"][PASS], e["counts"][FAIL])}
                )
        return result

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with closing(self._conn()) as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            return self._summary(conn, row, True) if row else None

    def list_scans(self) -> list[dict[str, Any]]:
        with closing(self._conn()) as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC, rowid DESC").fetchall()
            return [self._summary(conn, r, False) for r in rows]

    def list_findings(self, scan_id: str, filters: dict[str, str | None], page: int, page_size: int) -> dict[str, Any]:
        clauses, params = ["scan_id=?"], [scan_id]
        for column in ("status", "severity", "provider", "account_id", "check_id"):
            value = filters.get(column)
            if value:
                clauses.append(f"LOWER({column}) = LOWER(?)")
                params.append(value)
        where = " AND ".join(clauses)
        with closing(self._conn()) as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM findings WHERE {where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM findings WHERE {where} {_ORDER} LIMIT ? OFFSET ?",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        items = [{k: r[k] for k in r.keys()} for r in rows]
        return {"items": items, "total": total, "page": page, "page_size": page_size}

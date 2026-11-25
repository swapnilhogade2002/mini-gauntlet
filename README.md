# Mini Gauntlet

A small cloud posture scanner: a Python API runs ten security checks over a JSON snapshot of AWS, Azure and Google Cloud accounts, stores the findings, and a React dashboard shows scores and findings.

**CI:** _paste the link to the green run of the final commit here_

## Run it

```bash
docker compose up --build
```

Dashboard: <http://localhost:3000> · API: <http://localhost:8000/api/health> · Interactive API docs: <http://localhost:8000/docs>

Data is kept in the `gauntlet-db` volume. The snapshot is `data/inventory.json` (mounted read-only; override with `INVENTORY_PATH`).

## Run the tests

```bash
cd backend  && pip install -r requirements-dev.txt && ruff check . && mypy app && pytest
cd frontend && npm ci && npm run lint && npx tsc --noEmit && npm test
```

Local dev without Docker: `cd backend && INVENTORY_PATH=../data/inventory.json uvicorn app.main:create_app --factory`, and `cd frontend && npm run dev` (Vite proxies `/api` to port 8000).

Configuration: `INVENTORY_PATH`, `DATABASE_PATH`, `SCAN_WORKERS` (default 4), `SCAN_LATENCY_SCALE` (tests set 0), `LOG_LEVEL`.

## Architecture

```
React dashboard (nginx :3000) --/api--> FastAPI (:8000) --starts--> scanner engine (4 worker threads)
                                             |                          reads inventory.json
                                             +---- SQLite (volume) <---- findings
```

- `backend/app/checks/`: the registry (`registry.py`) and one module per provider. A check is one function decorated with `@register(...)`; every module in the package is imported automatically, so adding a check touches no other file.
- `backend/app/engine.py`: loads the snapshot, applies the CANNOT_SCAN rules, scans accounts in a `ThreadPoolExecutor` (4 workers by default, so the snapshot takes about 3 s instead of 8 s).
- `backend/app/db.py`: SQLite storage, filtering, ordering and pagination in SQL.
- `backend/app/main.py`: REST endpoints. Scans run on a background thread.
- `frontend/src/`: Scans page, Scan page, API client. Polls every 1.5 s while a scan is running.

Expected result for the supplied snapshot: 49 findings, 27 PASS, 18 FAIL, 4 CANNOT_SCAN, overall score 60.0.

## Decisions, assumptions and trade-offs

- **`public_access_block: null`** (S3) is treated as FAIL: nothing blocks public access.
- **Missing or non-boolean fields** (for example `mfa_enabled` absent) give CANNOT_SCAN rather than a guess.
- **A rule that fails beats one that can't be read:** if one rule of a security group is FAIL and another is malformed, the resource is FAIL; it is CANNOT_SCAN only when nothing definite is wrong.
- **Key age** is `snapshot_taken_at - created_at`; exactly 90 days passes, 91 fails. Inactive keys are ignored. Non-console IAM users PASS the MFA check.
- **Azure NSG:** only inbound `Allow` rules whose source is `*`, `Internet`, `Any`, `0.0.0.0/0` or `::/0` count; rule priorities are not simulated, so a higher-priority Deny does not cancel an Allow.
- **"All traffic" rules** (`-1`, `all`, GCP `tcp` with no ports) are FAIL because they include 22 and 3389. Only TCP counts as SSH/RDP.
- **Untrusted input:** strings from the snapshot are clipped and stripped of control characters before they go into `details`, and the dashboard renders them as React text nodes (ESLint forbids `dangerouslySetInnerHTML`; a test renders the `<img onerror>` payload as text).
- **Scores** round half up to one decimal.
- **SQLite and threads:** one connection per call with WAL mode. Simple and enough for one API container; PostgreSQL would replace it for several (see DEPLOY.md). A scan left RUNNING by a restart is marked FAILED on startup.
- **Findings are written once, when the scan completes**, so a scan's findings are all-or-nothing.
- **Nginx proxies `/api`** so the browser needs no CORS.

## What's unfinished / next

No stretch goals. Next: stream findings per account as each finishes, an API key on `POST /api/scans`, a CSV export, scan comparison, and image scanning in CI. Docker files and the compose stack follow the brief; run `docker compose up --build` once on your machine before relying on them.

## Time and AI use

| Part | Time |
|---|---|
| Scanner engine and checks | _fill in_ |
| API | _fill in_ |
| Dashboard | _fill in_ |
| Tests | _fill in_ |
| Docker, CI | _fill in_ |
| DEPLOY.md, README | _fill in_ |

**AI assistants:** _be specific and honest here_, for example: "I used Claude to generate the first version of the backend, dashboard, Dockerfiles, CI and docs. I reviewed and ran everything, and can explain every file."

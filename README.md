# Mini Gauntlet – Cloud Security Posture Scanner

A lightweight cloud security posture scanner built with **Python, FastAPI, React, and SQLite**. Mini Gauntlet evaluates AWS, Azure, and Google Cloud inventory snapshots against security rules, identifies potential security misconfigurations, and presents security findings through an interactive dashboard.

The application supports automated security checks, risk scoring, background scanning, and persistent finding storage.

## Key Features

- **Multi-cloud support:** Security checks for AWS, Azure, and Google Cloud.
- **10 security checks:** Evaluates cloud resources against predefined security rules.
- **Automated scanning:** Executes checks across cloud accounts using a concurrent worker pool.
- **Security findings:** Classifies results as PASS, FAIL, or CANNOT_SCAN.
- **Risk scoring:** Calculates an overall security score based on scan results.
- **Interactive dashboard:** Displays scan history, security scores, and detailed findings.
- **Background processing:** Runs scans asynchronously without blocking API requests.
- **Persistent storage:** Stores scan results and findings in SQLite.
- **Input validation:** Handles missing, malformed, and untrusted inventory data safely.
- **Containerized deployment:** Supports running the application using Docker Compose.

## Technology Stack

| Component | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React, TypeScript |
| Database | SQLite |
| Concurrency | ThreadPoolExecutor |
| API | REST API |
| Web Server | Nginx |
| Containerization | Docker, Docker Compose |
| Testing | Pytest, Ruff, Mypy, ESLint, TypeScript |

## Architecture

```text
                React Dashboard
                      |
                  Nginx (:3000)
                      |
                  /api Proxy
                      |
                FastAPI (:8000)
                      |
              Background Scan Engine
                      |
              ThreadPoolExecutor
                (4 Workers)
                      |
          AWS / Azure / GCP Checks
                      |
                JSON Inventory
                      |
                SQLite Database
                      |
              Security Findings
                      |
              React Dashboard
```

## Project Structure

```text
mini-gauntlet/
│
├── backend/
│   └── app/
│       ├── checks/
│       │   ├── registry.py
│       │   ├── aws.py
│       │   ├── azure.py
│       │   └── gcp.py
│       ├── engine.py
│       ├── db.py
│       └── main.py
│
├── frontend/
│   └── src/
│
├── data/
│   └── inventory.json
│
├── docker-compose.yml
├── DEPLOY.md
└── README.md
```

## Getting Started

### Prerequisites

- Docker Desktop
- Docker Compose

### Run the application

Clone the repository:

```bash
git clone https://github.com/swapnilhogade2002/mini-gauntlet.git
cd mini-gauntlet
```

Build and start the application:

```bash
docker compose up --build
```

### Application URLs

| Service | URL |
|---|---|
| React Dashboard | http://localhost:3000 |
| Backend API Health | http://localhost:8000/api/health |
| Interactive API Documentation | http://localhost:8000/docs |

Data is persisted using the `gauntlet-db` Docker volume.

The inventory snapshot is located at `data/inventory.json` and is mounted as read-only.

## Running Locally Without Docker

### Backend

```bash
cd backend

python -m venv venv

# Windows PowerShell
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt

$env:INVENTORY_PATH="../data/inventory.json"

uvicorn app.main:create_app --factory --reload --port 8000
```

### Frontend

Open another terminal:

```bash
cd frontend

npm ci

npm run dev
```

Vite proxies `/api` requests to the backend running on port 8000.

## Running Tests

### Backend

```bash
cd backend

pip install -r requirements-dev.txt

ruff check .
mypy app
pytest
```

### Frontend

```bash
cd frontend

npm ci

npm run lint
npx tsc --noEmit
npm test
```

## Security Evaluation Logic

The scanner uses three result categories:

| Status | Description |
|---|---|
| PASS | Security configuration satisfies the check |
| FAIL | A definite security misconfiguration is identified |
| CANNOT_SCAN | Required information is missing or invalid |

### Important Security Decisions

- Missing or non-boolean security fields return CANNOT_SCAN rather than assuming a secure configuration.
- S3 public access block set to `null` is treated as FAIL.
- A definite security failure takes priority over malformed rules.
- IAM access key age is calculated using the snapshot timestamp.
- Keys older than 90 days fail the age check; exactly 90 days passes.
- Inactive access keys are excluded from the age check.
- Network rules allowing all traffic are treated as security failures when they expose SSH or RDP.
- Untrusted inventory strings are sanitized before being included in finding details.
- The dashboard renders user-controlled values as React text rather than raw HTML.

## Expected Scan Results

For the supplied inventory snapshot, the expected results are:

| Metric | Expected Result |
|---|---:|
| Total Findings | 49 |
| PASS | 27 |
| FAIL | 18 |
| CANNOT_SCAN | 4 |
| Overall Security Score | 60.0 |

## Engineering Decisions

**Extensible check registry:** Security checks are registered using decorators. Provider modules are automatically imported, allowing new checks to be added without modifying the central scanning engine.

**Concurrent execution:** A ThreadPoolExecutor processes accounts using four worker threads by default.

**Background processing:** Scans execute in background threads, allowing the API to remain responsive.

**Database management:** SQLite uses WAL mode and separate connections per database operation. Filtering, sorting, and pagination are handled at the SQL level.

**Failure recovery:** Scans left in RUNNING state after an application restart are marked FAILED during startup.

**Atomic finding persistence:** Findings are stored after scan completion, ensuring that incomplete scans do not partially populate the findings table.

**Frontend security:** React renders inventory-derived content safely as text nodes.

**Reverse proxy:** Nginx forwards `/api` requests to FastAPI, avoiding the need for browser-side CORS configuration.

## Future Improvements

Potential enhancements include:

- Streaming findings as individual accounts finish scanning.
- API-key authentication for scan creation.
- CSV export for security findings.
- Comparison between historical scans.
- Container image security scanning in CI.
- PostgreSQL support for multi-instance deployments.

## Configuration

The application supports the following environment variables:

| Variable | Description |
|---|---|
| `INVENTORY_PATH` | Path to the cloud inventory JSON |
| `DATABASE_PATH` | SQLite database location |
| `SCAN_WORKERS` | Number of concurrent scan workers (default: 4) |
| `SCAN_LATENCY_SCALE` | Controls simulated scan latency |
| `LOG_LEVEL` | Application logging level |

## Author

**Swapnil Sunil Hogade**

Software Developer | Python Backend Developer

**GitHub:** https://github.com/swapnilhogade2002

**Project Repository:** https://github.com/swapnilhogade2002/mini-gauntlet

---

*Mini Gauntlet – A practical implementation of multi-cloud security posture assessment using Python, FastAPI, React, and SQLite.*
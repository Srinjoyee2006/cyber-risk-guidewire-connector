# CyberRisk-Guidewire-Connector (CRGC)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Simulated PolicyCenter](https://img.shields.io/badge/Guidewire%20PolicyCenter-10.2.1%20(Simulated)-amber.svg)]()

> **Enterprise Cyber Vulnerability Intelligence, Deterministic Risk Scoring, Coverage Gap Analysis, and Simulated Guidewire PolicyCenter Underwriting Advisory Platform.**

---

## Governance & Simulation Disclaimers

1. **Simulated Guidewire Integration:** CRGC executes strictly against a local deterministic **Mock PolicyCenter 10.2.1** adapter (`MockPolicyCenterAdapter`). No live Guidewire PolicyCenter instance is connected.
2. **No Automatic Policy Modifications:** CRGC operates purely as a decision-support service. No real insurance policy, premium, deductible, sublimit, or coverage is automatically modified, endorsed, bound, or cancelled. `APPROVED` and `DECLINED` decisions require explicit human underwriter action.
3. **Deterministic Engineering Rules (Not Actuarial Loss Predictions):** Risk scoring (`RiskEngine`) and vulnerability prioritization (`P1–P4`) use transparent, deterministic engineering benchmarks—not actuarially calibrated statistical loss models or black-box ML.
4. **Coverage Analysis Is Not Legal Advice:** Coverage gap evaluations and simplified hypothetical loss scenarios (`CoverageEngine`) are analytical aids only and do not constitute legal policy interpretation or binding claims adjudication.
5. **Simulated or Supplied Telemetry:** Organization posture telemetry and scanner observations may be supplied via API/CSV or simulated from test scenarios. Public CVE feeds (NVD/CISA KEV) alone do not establish organization impact.

---

## 1. System Overview & End-to-End Capabilities (Phases 1A–1F)

- **Phase 1A – Public Vulnerability Intelligence:** Ingests CVE feeds from **NIST NVD API 2.0** and exploitation data from the **CISA Known Exploited Vulnerabilities (KEV)** catalog, normalized with **P1–P4** deterministic triage prioritization.
- **Phase 1B – Organization Asset Matching:** Manages authorized organizations (`data_authorization_status == GRANTED`), ingests CSV asset inventories and scanner vulnerability observations (max 5 MB `.csv`), and distinguishes scanner-confirmed findings from prospective CPE applicability matches.
- **Phase 1C – Continuous Telemetry & Deterministic Risk Engine:** Persists telemetry posture snapshots and evaluates an explainable risk score (`0.0–100.0`):
  $$\text{Score} = \text{clamp}\bigl(5.0 + \text{MFA\_Penalty} + \text{RDP\_Penalty} + \text{Critical\_CVE\_Aging\_Penalty} + \text{EDR\_Penalty},\; 0.0,\; 100.0\bigr)$$
  Deduplicates identical CVEs across multiple scanners/assets while preserving affected asset counts and evidence snapshots.
- **Phase 1D – Policy Coverage Gap Engine:** Evaluates cyber insurance policy limits, sublimits, deductibles, waiting periods, coinsurance, and coverage clarity across 8 categories, modeling simplified hypothetical loss outcomes (covered vs. uninsured gaps).
- **Phase 1E & 1F – Unified Underwriting Review Workflow:** Routes qualifying assessments (`Score > 60.0`, `REVIEW_REQUIRED`) through `UnderwritingService` to create idempotent, immutable review records backed by a strict workflow state machine (`PENDING` $\to$ `DISPATCHED` $\to$ `ACKNOWLEDGED` $\to$ `IN_REVIEW` $\to$ `APPROVED` / `DECLINED` $\to$ `CLOSED`) and persistent simulated PolicyCenter activity tracking.

---

## 2. Technology Stack

- **Backend:** Python 3.10+, FastAPI, SQLAlchemy 2.x, Pydantic v2, Alembic, HTTPX, SQLite (`crgc.db`).
- **Security:** OAuth2 Password/Bearer flow with HMAC-SHA256 JWT tokens and PBKDF2-HMAC-SHA256 salted password hashes, plus organization-level data authorization isolation (`GRANTED` vs `REVOKED`/`PENDING`) and CORS origin restrictions.
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Lucide Icons, Recharts, Vitest + React Testing Library.

---

## 3. Setup, Database & Configuration

### Prerequisites
- Python 3.10+
- Node.js 20+ and npm

### 1. Backend Setup
```bash
cd cyber-risk-platform
python -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

pip install -e ".[dev]"
```

### 2. Environment Configuration (`.env`)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

For local academic/development demonstration authentication, set non-production development credentials in `.env`:
```env
APP_ENV="development"
JWT_SECRET_KEY="your-local-dev-jwt-secret"
DEMO_AUTH_ENABLED=true
DEMO_UNDERWRITER_PASSWORD="your-dev-underwriter-password"
DEMO_ADMIN_PASSWORD="your-dev-admin-password"
CORS_ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
```
> **Note:** Demo user accounts (`underwriter_demo`, `admin_demo`) are automatically disabled when `APP_ENV` is set to `production` or `staging`. Production environments must explicitly configure `JWT_SECRET_KEY`.

### 3. Database & Migrations (Alembic)
To inspect or apply migrations to the configured database:
```bash
alembic current
alembic upgrade head
```

### 4. Frontend Setup
```bash
npm --prefix frontend install
```

---

## 4. Running the Application

### Start Backend API Server
```bash
# Inside activated virtual environment
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- **API Swagger Documentation:** http://127.0.0.1:8000/docs
- **Health Probe:** http://127.0.0.1:8000/health

### Start Frontend UI Server
```bash
npm --prefix frontend run dev
```
- **Web Interface:** http://localhost:5173

To perform write operations or underwriting status transitions in the UI, click **Sign In** in the top navigation bar and enter your configured development user credentials (e.g., `underwriter_demo`).

---

## 5. Running Tests & Production Builds

### Backend Tests (Isolated Test Database)
All automated tests execute against an isolated temporary SQLite database configured in `tests/conftest.py` (`%TEMP%\crgc_test_isolated.db`). **Tests never touch or modify `crgc.db`.**
```bash
.\.venv\Scripts\pytest.exe -vv tests
```

### Frontend Unit Tests & Production Build
```bash
npm --prefix frontend test
npm --prefix frontend run build
```

---

## 6. Architecture Documentation
Detailed component diagrams, database tables, API contracts, and security boundaries are documented in [ARCHITECTURE.md](ARCHITECTURE.md).

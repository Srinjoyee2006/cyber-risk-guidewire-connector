# CRGC Vulnerability Intelligence & Prioritization Frontend

A modern React + TypeScript + Vite + Tailwind CSS dashboard providing a user interface for the Cyber Vulnerability Intelligence & Prioritization Service.

---

## 1. System Positioning & Underwriting Boundary

> **Critical Notice**:  
> Public vulnerability intelligence (from NIST NVD and CISA KEV) provides empirical threat metrics, attack vectors, weaponization status, and remediation due dates.  
> It does **NOT** establish that any insured organization or policyholder has that software deployed or is affected.  
> The UI explicitly displays:  
> *"Insured impact is unknown until authorized asset or vulnerability-scanner evidence is available."*

---

## 2. Screens & Capabilities

1. **Overview (`/`)**:
   - Total ingested vulnerabilities count.
   - CISA KEV known-exploited count.
   - Deterministic prioritization counts across priority bands (`P1`, `P2`, `P3`, `P4`).
   - Feed synchronization status for NIST NVD API 2.0 and CISA KEV catalog.
   - Quick highlights of prioritized critical threats.
   - Prominent Underwriting Boundary Notice banner.

2. **Vulnerability Explorer (`/vulnerabilities`)**:
   - Search by CVE ID or partial CVE number (e.g., `CVE-2024-38077` or `38077`).
   - Server-side query parameter filtering:
     - Priority band (`P1`, `P2`, `P3`, `P4`)
     - CISA KEV status (`true`, `false`)
     - Minimum CVSS score (`>= minimum_cvss`)
     - Qualitative severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
     - Published date (`published_after`)
   - Interactive button to trigger batch prioritization runs.

3. **Vulnerability Detail (`/vulnerabilities/:cveId`)**:
   - CVE identifier, description, source, and review status.
   - CVSS base score, vector string, CWE weaknesses, and CPE criteria.
   - CISA KEV exploitation telemetry: date added, due date, ransomware campaign use, and prescribed action.
   - Latest explainable prioritization score, priority band, ruleset version, and assessment timestamp.
   - Full rule-by-rule factor evaluation table detailing whether each rule was triggered, its score contribution, empirical evidence, and threat rationale.
   - Vendor advisory and patch links.
   - Prominent card stating: *"Insured impact is unknown until authorized asset or vulnerability-scanner evidence is available."*

4. **Ingestion Runs (`/ingestion`)**:
   - Historical audit log of all NVD and CISA KEV ingestion jobs.
   - Status (`SUCCESS`, `PARTIAL_SUCCESS`, `FAILED`), timestamps, records received, inserted, updated, and skipped.
   - Action buttons to trigger NVD and CISA KEV ingestion jobs with confirmation dialogues.

---

## 3. Setup & Running Instructions

### Prerequisites
- Node.js `v20+` or `v24+` (tested on `v24.14.0`)
- npm `10+` or `11+`
- CRGC FastAPI backend running on `http://127.0.0.1:8000`

### Step 1: Install Dependencies
From the `cyber-risk-platform/frontend` directory:
```bash
cd cyber-risk-platform/frontend
npm install
```

### Step 2: Configure Environment
A default `.env` file is provided:
```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```
If your backend runs on a different port or host, adjust `VITE_API_BASE_URL` accordingly.

### Step 3: Start the Development Server
```bash
npm run dev
```
Open your browser at `http://127.0.0.1:5173`.

### Step 4: Run Frontend Unit & Integration Tests
```bash
npm test
```
Runs 9 Vitest test cases covering:
- Boundary notice rendering and wording across all component variants
- Badge states (Priority `P1`-`P4`, CISA KEV, CVSS)
- Overview page data loading, statistics calculation, error states, and retry actions

### Step 5: Build Production Bundle
```bash
npm run build
```
Creates an optimized static bundle in `dist/`.

---

## 4. Architecture & API Integration

- **Centralized Client**: All API communication is routed through [src/services/apiClient.ts](file:///d:/New%20folder/cyber-risk-platform/frontend/src/services/apiClient.ts).
- **Backend Grounding**: Every frontend query matches the FastAPI backend's OpenAPI contract:
  - `GET /api/v1/vulnerabilities`
  - `GET /api/v1/vulnerabilities/{cve_id}`
  - `GET /api/v1/prioritization/results`
  - `GET /api/v1/prioritization/results/{cve_id}`
  - `POST /api/v1/prioritization/run`
  - `GET /api/v1/ingestion/runs`
  - `POST /api/v1/ingestion/nvd/run`
  - `POST /api/v1/ingestion/kev/run`
- **Security & Privacy**: No external API keys or secrets are packaged in or exposed to the client.

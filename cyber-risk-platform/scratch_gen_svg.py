import os

def create_svgs():
    out_dir = r"d:\New folder\report_materials"

    # Common styles and defs
    defs = '''
    <defs>
        <linearGradient id="blueGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#eff6ff" />
            <stop offset="100%" stop-color="#dbeafe" />
        </linearGradient>
        <linearGradient id="purpleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#faf5ff" />
            <stop offset="100%" stop-color="#f3e8ff" />
        </linearGradient>
        <linearGradient id="amberGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#fffbeb" />
            <stop offset="100%" stop-color="#fef3c7" />
        </linearGradient>
        <linearGradient id="emeraldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#ecfdf5" />
            <stop offset="100%" stop-color="#d1fae5" />
        </linearGradient>
        <linearGradient id="roseGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#fff1f2" />
            <stop offset="100%" stop-color="#ffe4e6" />
        </linearGradient>
        <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%" filterUnits="userSpaceOnUse">
            <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.15" />
        </filter>
        <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
        </marker>
        <marker id="arrowBlue" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#2563eb" />
        </marker>
    </defs>
    '''

    # =========================================================================
    # Figure A: Overall System Architecture
    # =========================================================================
    svg_a = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1100 850" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="1060" height="45" rx="8" fill="#1e293b" />
    <text x="550" y="43" fill="#ffffff" font-size="18" font-weight="bold" text-anchor="middle">Figure 4.1: CRGC High-Level Multi-Tier System Architecture</text>
    
    <!-- Presentation Tier -->
    <rect x="30" y="80" width="1040" height="110" rx="8" fill="url(#blueGrad)" stroke="#3b82f6" stroke-width="1.5" filter="url(#shadow)" />
    <text x="50" y="105" fill="#1e3a8a" font-size="14" font-weight="bold">PRESENTATION TIER (React 19 / TypeScript / Vite / Tailwind CSS)</text>
    <rect x="50" y="115" width="180" height="60" rx="6" fill="#ffffff" stroke="#93c5fd" />
    <text x="140" y="140" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Overview Dashboard</text>
    <text x="140" y="158" fill="#64748b" font-size="10" text-anchor="middle">Live Counts &amp; Sync Runs</text>
    
    <rect x="250" y="115" width="180" height="60" rx="6" fill="#ffffff" stroke="#93c5fd" />
    <text x="340" y="140" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Vulnerability Explorer</text>
    <text x="340" y="158" fill="#64748b" font-size="10" text-anchor="middle">CVE / KEV Search &amp; Triage</text>

    <rect x="450" y="115" width="180" height="60" rx="6" fill="#ffffff" stroke="#93c5fd" />
    <text x="540" y="140" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Priority Configuration</text>
    <text x="540" y="158" fill="#64748b" font-size="10" text-anchor="middle">Rule Weights &amp; Thresholds</text>

    <rect x="650" y="115" width="180" height="60" rx="6" fill="#ffffff" stroke="#93c5fd" />
    <text x="740" y="140" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Observed Findings</text>
    <text x="740" y="158" fill="#64748b" font-size="10" text-anchor="middle">Enterprise Asset Scans</text>

    <rect x="850" y="115" width="200" height="60" rx="6" fill="#ffffff" stroke="#93c5fd" />
    <text x="950" y="140" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Underwriter Terminal</text>
    <text x="950" y="158" fill="#64748b" font-size="10" text-anchor="middle">Risk Evaluation &amp; Policy Actions</text>

    <!-- Downward Flow Arrow -->
    <path d="M 550 190 L 550 215" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />
    <text x="560" y="208" fill="#2563eb" font-size="11" font-weight="bold">JSON over REST HTTP</text>

    <!-- API Tier -->
    <rect x="30" y="225" width="1040" height="110" rx="8" fill="url(#purpleGrad)" stroke="#8b5cf6" stroke-width="1.5" filter="url(#shadow)" />
    <text x="50" y="250" fill="#581c87" font-size="14" font-weight="bold">APPLICATION API TIER (FastAPI v0.115.6 / Pydantic v2 / Uvicorn)</text>
    
    <rect x="50" y="260" width="220" height="60" rx="6" fill="#ffffff" stroke="#c4b5fd" />
    <text x="160" y="285" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">/api/v1/vulnerabilities</text>
    <text x="160" y="303" fill="#64748b" font-size="10" text-anchor="middle">List, Detail, NVD Ingest</text>

    <rect x="290" y="260" width="220" height="60" rx="6" fill="#ffffff" stroke="#c4b5fd" />
    <text x="400" y="285" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">/api/v1/prioritizations</text>
    <text x="400" y="303" fill="#64748b" font-size="10" text-anchor="middle">P1-P4 Evaluation &amp; Audits</text>

    <rect x="530" y="260" width="240" height="60" rx="6" fill="#ffffff" stroke="#c4b5fd" />
    <text x="650" y="285" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">/api/v1/organizations &amp; assets</text>
    <text x="650" y="303" fill="#64748b" font-size="10" text-anchor="middle">Tenant &amp; Inventory Governance</text>

    <rect x="790" y="260" width="260" height="60" rx="6" fill="#ffffff" stroke="#c4b5fd" />
    <text x="920" y="285" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">/api/v1/underwriting/evaluate</text>
    <text x="920" y="303" fill="#64748b" font-size="10" text-anchor="middle">RiskEngine &amp; Guidewire Gateway</text>

    <!-- Mid Flow Arrow -->
    <path d="M 550 335 L 550 360" stroke="#475569" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Analytics & Core Engine Tier -->
    <rect x="30" y="370" width="1040" height="120" rx="8" fill="url(#amberGrad)" stroke="#f59e0b" stroke-width="1.5" filter="url(#shadow)" />
    <text x="50" y="395" fill="#78350f" font-size="14" font-weight="bold">CORE PROCESSING &amp; ANALYTICS ENGINES</text>

    <rect x="50" y="405" width="230" height="70" rx="6" fill="#ffffff" stroke="#fcd34d" />
    <text x="165" y="430" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">NVD / CISA Ingestion</text>
    <text x="165" y="448" fill="#64748b" font-size="10" text-anchor="middle">HTTPX Async Clients &amp; Stream Parsers</text>
    <text x="165" y="463" fill="#059669" font-size="9" text-anchor="middle">Idempotent Deduplication</text>

    <rect x="300" y="405" width="240" height="70" rx="6" fill="#ffffff" stroke="#fcd34d" />
    <text x="420" y="430" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">PrioritizationEngine</text>
    <text x="420" y="448" fill="#64748b" font-size="10" text-anchor="middle">Base CVSS + KEV (+30) + Ransom (+15)</text>
    <text x="420" y="463" fill="#b45309" font-size="9" font-weight="600" text-anchor="middle">Outputs P1, P2, P3, P4 Tiers</text>

    <rect x="560" y="405" width="240" height="70" rx="6" fill="#ffffff" stroke="#fcd34d" />
    <text x="680" y="430" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Organization RiskEngine</text>
    <text x="680" y="448" fill="#64748b" font-size="10" text-anchor="middle">Base 5 + MFA + RDP + CVE + EDR</text>
    <text x="680" y="463" fill="#b45309" font-size="9" font-weight="600" text-anchor="middle">Score Clamped to [0.0, 100.0]</text>

    <rect x="820" y="405" width="230" height="70" rx="6" fill="#ffffff" stroke="#fcd34d" />
    <text x="935" y="430" fill="#1e293b" font-size="12" font-weight="600" text-anchor="middle">Coverage &amp; Policy Engine</text>
    <text x="935" y="448" fill="#64748b" font-size="10" text-anchor="middle">Deductibles &amp; Policy Actions</text>
    <text x="935" y="463" fill="#0284c7" font-size="9" font-weight="600" text-anchor="middle">Nominal / Monitor / Review Req</text>

    <!-- Lower Flow Arrows -->
    <path d="M 300 490 L 300 525" stroke="#475569" stroke-width="2" marker-end="url(#arrow)" />
    <path d="M 850 490 L 850 525" stroke="#8b5cf6" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Persistence Tier (Left) -->
    <rect x="30" y="535" width="560" height="280" rx="8" fill="url(#emeraldGrad)" stroke="#10b981" stroke-width="1.5" filter="url(#shadow)" />
    <text x="50" y="560" fill="#064e3b" font-size="14" font-weight="bold">PERSISTENCE TIER (SQLAlchemy 2.0 / SQLite 3 - cyber_risk.db)</text>
    
    <g transform="translate(50, 575)">
        <rect x="0" y="0" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="10" y="18" fill="#047857" font-size="11" font-weight="bold">data_ingestion_runs</text>
        <text x="10" y="32" fill="#64748b" font-size="9">UUID, feed, timestamps, status, counts</text>

        <rect x="260" y="0" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="270" y="18" fill="#047857" font-size="11" font-weight="bold">vulnerabilities</text>
        <text x="270" y="32" fill="#64748b" font-size="9">CVE PK, description, CVSS v3/v2</text>

        <rect x="0" y="52" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="10" y="70" fill="#047857" font-size="11" font-weight="bold">exploitation_status</text>
        <text x="10" y="84" fill="#64748b" font-size="9">CVE FK, KEV flag, dates, ransomware</text>

        <rect x="260" y="52" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="270" y="70" fill="#047857" font-size="11" font-weight="bold">vulnerability_prioritizations</text>
        <text x="270" y="84" fill="#64748b" font-size="9">Priority UUID, score, tier, audit JSON</text>

        <rect x="0" y="104" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="10" y="122" fill="#047857" font-size="11" font-weight="bold">organizations</text>
        <text x="10" y="136" fill="#64748b" font-size="9">Org UUID, ref UK, name, consent flag</text>

        <rect x="260" y="104" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="270" y="122" fill="#047857" font-size="11" font-weight="bold">assets</text>
        <text x="270" y="136" fill="#64748b" font-size="9">Asset UUID, Org FK, hostname, IP, type</text>

        <rect x="130" y="156" width="240" height="42" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="140" y="174" fill="#047857" font-size="11" font-weight="bold">vulnerability_observations</text>
        <text x="140" y="188" fill="#64748b" font-size="9">Obs UUID, Asset FK, CVE FK, scanner</text>
    </g>

    <!-- External Feeds & Guidewire Mock (Right) -->
    <rect x="610" y="535" width="460" height="135" rx="8" fill="url(#roseGrad)" stroke="#f43f5e" stroke-width="1.5" filter="url(#shadow)" />
    <text x="630" y="560" fill="#881337" font-size="13" font-weight="bold">EXTERNAL THREAT INTELLIGENCE (LIVE HTTPS)</text>
    <rect x="630" y="575" width="205" height="75" rx="6" fill="#ffffff" stroke="#fecdd3" />
    <text x="732" y="598" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">NIST NVD API 2.0</text>
    <text x="732" y="615" fill="#64748b" font-size="9" text-anchor="middle">services.nvd.nist.gov</text>
    <text x="732" y="632" fill="#059669" font-size="9" font-weight="bold" text-anchor="middle">Live JSON CVE Feed</text>

    <rect x="845" y="575" width="205" height="75" rx="6" fill="#ffffff" stroke="#fecdd3" />
    <text x="947" y="598" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">CISA KEV Catalog</text>
    <text x="947" y="615" fill="#64748b" font-size="9" text-anchor="middle">cisa.gov/feeds</text>
    <text x="947" y="632" fill="#059669" font-size="9" font-weight="bold" text-anchor="middle">1,739+ Active Exploits</text>

    <!-- Guidewire Integration Layer -->
    <rect x="610" y="680" width="460" height="135" rx="8" fill="url(#purpleGrad)" stroke="#8b5cf6" stroke-width="1.5" filter="url(#shadow)" />
    <text x="630" y="705" fill="#4c1d95" font-size="13" font-weight="bold">GUIDEWIRE POLICYCENTER INTEGRATION (SIMULATED)</text>
    <rect x="630" y="720" width="420" height="75" rx="6" fill="#ffffff" stroke="#ddd6fe" />
    <text x="840" y="742" fill="#6b21a8" font-size="12" font-weight="bold" text-anchor="middle">Guidewire Mock Adapter (GW_MOCK_MODE=True)</text>
    <text x="840" y="760" fill="#64748b" font-size="10" text-anchor="middle">Simulates PolicyCenter Underwriting File Activities &amp; Referral Notes</text>
    <text x="840" y="777" fill="#d97706" font-size="9" font-weight="bold" text-anchor="middle">Architecturally Compliant; No Live Production Guidewire Account Required</text>
</svg>'''
    with open(os.path.join(out_dir, "figure_a_system_architecture.svg"), "w", encoding="utf-8") as f:
        f.write(svg_a.strip())

    # =========================================================================
    # Figure B: Vulnerability Ingestion Workflow
    # =========================================================================
    svg_b = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 650" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="960" height="40" rx="6" fill="#1e293b" />
    <text x="500" y="41" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle">Figure 4.2: Dual-Stream Vulnerability Ingestion &amp; Normalization Pipeline</text>

    <!-- Left Box: NVD Pipeline -->
    <rect x="30" y="75" width="455" height="545" rx="8" fill="url(#blueGrad)" stroke="#3b82f6" stroke-width="1.5" filter="url(#shadow)" />
    <text x="50" y="102" fill="#1e3a8a" font-size="14" font-weight="bold">STREAM 1: NIST NVD CVE INGESTION</text>

    <!-- Steps for NVD -->
    <g transform="translate(50, 120)">
        <rect x="0" y="0" width="415" height="55" rx="6" fill="#ffffff" stroke="#93c5fd" />
        <text x="15" y="24" fill="#1e3a8a" font-size="12" font-weight="bold">1. Ingestion Request Triggered</text>
        <text x="15" y="42" fill="#64748b" font-size="10">Targeted CVE (e.g. CVE-2021-44228) or Range (startIndex, count)</text>

        <path d="M 207 55 L 207 75" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

        <rect x="0" y="75" width="415" height="55" rx="6" fill="#ffffff" stroke="#93c5fd" />
        <text x="15" y="99" fill="#1e3a8a" font-size="12" font-weight="bold">2. Audit Run Record Created</text>
        <text x="15" y="117" fill="#64748b" font-size="10">INSERT data_ingestion_runs with status='PENDING', feed='NVD'</text>

        <path d="M 207 130 L 207 150" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

        <rect x="0" y="150" width="415" height="55" rx="6" fill="#ffffff" stroke="#93c5fd" />
        <text x="15" y="174" fill="#1e3a8a" font-size="12" font-weight="bold">3. Upstream HTTP GET (services.nvd.nist.gov)</text>
        <text x="15" y="192" fill="#64748b" font-size="10">Asynchronous HTTPX client with exponential backoff on HTTP 403/429</text>

        <path d="M 207 205 L 207 225" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

        <rect x="0" y="225" width="415" height="65" rx="6" fill="#ffffff" stroke="#93c5fd" />
        <text x="15" y="248" fill="#1e3a8a" font-size="12" font-weight="bold">4. Schema Parsing &amp; Normalization</text>
        <text x="15" y="265" fill="#64748b" font-size="10">Extracts: CVSS v3.1 / v2.0 Base Score, Vector String, Description,</text>
        <text x="15" y="279" fill="#64748b" font-size="10">Publication Date, and Last Modified Date</text>

        <path d="M 207 290 L 207 310" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

        <rect x="0" y="310" width="415" height="65" rx="6" fill="#ffffff" stroke="#93c5fd" />
        <text x="15" y="333" fill="#1e3a8a" font-size="12" font-weight="bold">5. Idempotent Database Upsert</text>
        <text x="15" y="350" fill="#64748b" font-size="10">Upserts into 'vulnerabilities' table. New CVEs increment inserted count;</text>
        <text x="15" y="364" fill="#64748b" font-size="10">existing CVEs update metadata and increment updated count.</text>

        <path d="M 207 375 L 207 395" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

        <rect x="0" y="395" width="415" height="55" rx="6" fill="#ffffff" stroke="#93c5fd" />
        <text x="15" y="418" fill="#047857" font-size="12" font-weight="bold">6. Ingestion Telemetry Committed</text>
        <text x="15" y="436" fill="#64748b" font-size="10">UPDATE data_ingestion_runs: status='SUCCESS', records_fetched, etc.</text>
    </g>

    <!-- Right Box: CISA KEV Pipeline -->
    <rect x="515" y="75" width="455" height="545" rx="8" fill="url(#roseGrad)" stroke="#f43f5e" stroke-width="1.5" filter="url(#shadow)" />
    <text x="535" y="102" fill="#881337" font-size="14" font-weight="bold">STREAM 2: CISA KEV CATALOG INGESTION</text>

    <!-- Steps for KEV -->
    <g transform="translate(535, 120)">
        <rect x="0" y="0" width="415" height="55" rx="6" fill="#ffffff" stroke="#fecdd3" />
        <text x="15" y="24" fill="#881337" font-size="12" font-weight="bold">1. KEV Synchronization Triggered</text>
        <text x="15" y="42" fill="#64748b" font-size="10">Invoked via POST /api/v1/exploitation-status/ingest/cisa-kev</text>

        <path d="M 207 55 L 207 75" stroke="#e11d48" stroke-width="2" marker-end="url(#arrow)" />

        <rect x="0" y="75" width="415" height="55" rx="6" fill="#ffffff" stroke="#fecdd3" />
        <text x="15" y="99" fill="#881337" font-size="12" font-weight="bold">2. Audit Run Record Created</text>
        <text x="15" y="117" fill="#64748b" font-size="10">INSERT data_ingestion_runs with status='PENDING', feed='CISA_KEV'</text>

        <path d="M 207 130 L 207 150" stroke="#e11d48" stroke-width="2" marker-end="url(#arrow)" />

        <rect x="0" y="150" width="415" height="55" rx="6" fill="#ffffff" stroke="#fecdd3" />
        <text x="15" y="174" fill="#881337" font-size="12" font-weight="bold">3. Authoritative Feed Retrieval</text>
        <text x="15" y="192" fill="#64748b" font-size="10">Downloads complete JSON catalog from cisa.gov (1,739+ active CVEs)</text>

        <path d="M 207 205 L 207 225" stroke="#e11d48" stroke-width="2" marker-end="url(#arrow)" />

        <rect x="0" y="225" width="415" height="65" rx="6" fill="#ffffff" stroke="#fecdd3" />
        <text x="15" y="248" fill="#881337" font-size="12" font-weight="bold">4. Stream Validation &amp; Model Mapping</text>
        <text x="15" y="265" fill="#64748b" font-size="10">Pydantic models validate: cveID, dateAdded, dueDate,</text>
        <text x="15" y="279" fill="#64748b" font-size="10">knownRansomwareCampaignUse, and requiredAction</text>

        <path d="M 207 290 L 207 310" stroke="#e11d48" stroke-width="2" marker-end="url(#arrow)" />

        <rect x="0" y="310" width="415" height="65" rx="6" fill="#ffffff" stroke="#fecdd3" />
        <text x="15" y="333" fill="#881337" font-size="12" font-weight="bold">5. Relational Exploitation Linking</text>
        <text x="15" y="350" fill="#64748b" font-size="10">Upserts into 'exploitation_status' with kev_flag=True. Matches</text>
        <text x="15" y="364" fill="#64748b" font-size="10">existing CVEs in 'vulnerabilities' table to enrich threat posture.</text>

        <path d="M 207 375 L 207 395" stroke="#e11d48" stroke-width="2" marker-end="url(#arrow)" />

        <rect x="0" y="395" width="415" height="55" rx="6" fill="#ffffff" stroke="#fecdd3" />
        <text x="15" y="418" fill="#047857" font-size="12" font-weight="bold">6. Run Completion &amp; Count Verification</text>
        <text x="15" y="436" fill="#64748b" font-size="10">Records conclusion timestamp and accurate counts in run history.</text>
    </g>
</svg>'''
    with open(os.path.join(out_dir, "figure_b_ingestion_pipeline.svg"), "w", encoding="utf-8") as f:
        f.write(svg_b.strip())

    # =========================================================================
    # Figure C: Vulnerability Prioritization Workflow
    # =========================================================================
    svg_c = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 700" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="960" height="40" rx="6" fill="#1e293b" />
    <text x="500" y="41" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle">Figure 4.3: Heuristic Vulnerability Prioritization Workflow &amp; Tier Routing</text>

    <!-- Inputs Box -->
    <rect x="50" y="80" width="900" height="85" rx="8" fill="url(#blueGrad)" stroke="#3b82f6" stroke-width="1.5" filter="url(#shadow)" />
    <text x="70" y="105" fill="#1e3a8a" font-size="13" font-weight="bold">STEP 1: INGEST PUBLIC VULNERABILITY ATTRIBUTES</text>
    <rect x="70" y="115" width="260" height="38" rx="4" fill="#ffffff" stroke="#93c5fd" />
    <text x="200" y="139" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">CVSS Base Score (0.0 - 10.0)</text>
    <rect x="350" y="115" width="280" height="38" rx="4" fill="#ffffff" stroke="#93c5fd" />
    <text x="490" y="139" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">CISA KEV Exploitation Flag (True / False)</text>
    <rect x="650" y="115" width="280" height="38" rx="4" fill="#ffffff" stroke="#93c5fd" />
    <text x="790" y="139" fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">Known Ransomware Use (Known / Unknown)</text>

    <path d="M 500 165 L 500 195" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

    <!-- Step 2: Mathematical Computation Box -->
    <rect x="50" y="200" width="900" height="150" rx="8" fill="url(#amberGrad)" stroke="#f59e0b" stroke-width="1.5" filter="url(#shadow)" />
    <text x="70" y="225" fill="#78350f" font-size="13" font-weight="bold">STEP 2: MULTI-FACTOR HEURISTIC CALCULATION</text>
    
    <g transform="translate(70, 240)">
        <rect x="0" y="0" width="260" height="90" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="130" y="25" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Technical Severity Base</text>
        <text x="130" y="48" fill="#b45309" font-size="13" font-weight="bold" text-anchor="middle">S_base = CVSS * 10.0</text>
        <text x="130" y="70" fill="#64748b" font-size="10" text-anchor="middle">Scale: 0.0 to 100.0</text>

        <rect x="280" y="0" width="260" height="90" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="410" y="25" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Active Exploitation Penalty</text>
        <text x="410" y="48" fill="#b45309" font-size="13" font-weight="bold" text-anchor="middle">P_kev = +30.0 points</text>
        <text x="410" y="70" fill="#64748b" font-size="10" text-anchor="middle">Applied if kev_flag == True</text>

        <rect x="560" y="0" width="300" height="90" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="710" y="25" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Ransomware Campaign Multiplier</text>
        <text x="710" y="48" fill="#b45309" font-size="13" font-weight="bold" text-anchor="middle">P_ransom = +15.0 points</text>
        <text x="710" y="70" fill="#64748b" font-size="10" text-anchor="middle">Applied if ransomware == 'Known'</text>
    </g>

    <path d="M 500 350 L 500 380" stroke="#b45309" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Step 3: Clamping & Formula -->
    <rect x="200" y="380" width="600" height="60" rx="8" fill="#1e293b" filter="url(#shadow)" />
    <text x="500" y="405" fill="#ffffff" font-size="13" font-weight="bold" text-anchor="middle">STEP 3: COMPOSITE SCORE CLAMPING</text>
    <text x="500" y="425" fill="#38bdf8" font-size="12" font-family="monospace" font-weight="bold" text-anchor="middle">PriorityScore = min(100.0, max(0.0, S_base + P_kev + P_ransom))</text>

    <path d="M 500 440 L 500 470" stroke="#475569" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Step 4: Priority Tiers -->
    <text x="500" y="488" fill="#1e293b" font-size="13" font-weight="bold" text-anchor="middle">STEP 4: DETERMINISTIC SLA &amp; URGENCY TIER ROUTING</text>

    <g transform="translate(50, 505)">
        <rect x="0" y="0" width="210" height="110" rx="6" fill="#fee2e2" stroke="#ef4444" stroke-width="1.5" />
        <text x="105" y="28" fill="#991b1b" font-size="14" font-weight="bold" text-anchor="middle">TIER P1 (CRITICAL)</text>
        <text x="105" y="48" fill="#b91c1c" font-size="11" font-weight="bold" text-anchor="middle">Score &gt;= 75.0</text>
        <text x="105" y="70" fill="#7f1d1d" font-size="10" text-anchor="middle">Active weaponization / KEV</text>
        <text x="105" y="90" fill="#991b1b" font-size="10" font-weight="bold" text-anchor="middle">Remediation SLA: 72 Hours</text>

        <rect x="230" y="0" width="210" height="110" rx="6" fill="#ffedd5" stroke="#f97316" stroke-width="1.5" />
        <text x="335" y="28" fill="#9a3412" font-size="14" font-weight="bold" text-anchor="middle">TIER P2 (HIGH)</text>
        <text x="335" y="48" fill="#c2410c" font-size="11" font-weight="bold" text-anchor="middle">50.0 &lt;= Score &lt; 75.0</text>
        <text x="335" y="70" fill="#7c2d12" font-size="10" text-anchor="middle">High technical severity</text>
        <text x="335" y="90" fill="#9a3412" font-size="10" font-weight="bold" text-anchor="middle">Remediation SLA: 14 Days</text>

        <rect x="460" y="0" width="210" height="110" rx="6" fill="#fef3c7" stroke="#eab308" stroke-width="1.5" />
        <text x="565" y="28" fill="#854d0e" font-size="14" font-weight="bold" text-anchor="middle">TIER P3 (MEDIUM)</text>
        <text x="565" y="48" fill="#a16207" font-size="11" font-weight="bold" text-anchor="middle">25.0 &lt;= Score &lt; 50.0</text>
        <text x="565" y="70" fill="#713f12" font-size="10" text-anchor="middle">Moderate severity, unexploited</text>
        <text x="565" y="90" fill="#854d0e" font-size="10" font-weight="bold" text-anchor="middle">Remediation SLA: 30 Days</text>

        <rect x="690" y="0" width="210" height="110" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1.5" />
        <text x="795" y="28" fill="#334155" font-size="14" font-weight="bold" text-anchor="middle">TIER P4 (LOW)</text>
        <text x="795" y="48" fill="#475569" font-size="11" font-weight="bold" text-anchor="middle">Score &lt; 25.0</text>
        <text x="795" y="70" fill="#475569" font-size="10" text-anchor="middle">Low impact / informational</text>
        <text x="795" y="90" fill="#334155" font-size="10" font-weight="bold" text-anchor="middle">Routine Maintenance</text>
    </g>

    <!-- Step 5: Audit Persistence -->
    <rect x="50" y="635" width="900" height="40" rx="6" fill="#f0fdf4" stroke="#22c55e" />
    <text x="500" y="660" fill="#15803d" font-size="11" font-weight="bold" text-anchor="middle">Step 5: Persist Score, Tier, and Explainable Factor Breakdown JSON to 'vulnerability_prioritizations' Table</text>
</svg>'''
    with open(os.path.join(out_dir, "figure_c_prioritization_workflow.svg"), "w", encoding="utf-8") as f:
        f.write(svg_c.strip())

    # =========================================================================
    # Figure D: Database ERD
    # =========================================================================
    svg_d = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1100 780" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="1060" height="40" rx="6" fill="#1e293b" />
    <text x="550" y="41" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle">Figure 4.4: CRGC Database Entity-Relationship Diagram (SQLAlchemy Relational Schema)</text>

    <!-- Table 1: data_ingestion_runs -->
    <g transform="translate(30, 80)">
        <rect x="0" y="0" width="300" height="200" rx="6" fill="#ffffff" stroke="#0ea5e9" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="300" height="30" rx="6" fill="#0284c7" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">data_ingestion_runs</text>
        <text x="15" y="50" fill="#0369a1" font-size="11" font-weight="bold">PK  run_id : UUID</text>
        <text x="15" y="70" fill="#334155" font-size="11">    feed_type : VARCHAR(50)</text>
        <text x="15" y="90" fill="#334155" font-size="11">    started_at : DATETIME</text>
        <text x="15" y="110" fill="#334155" font-size="11">    completed_at : DATETIME</text>
        <text x="15" y="130" fill="#334155" font-size="11">    status : VARCHAR(20)</text>
        <text x="15" y="150" fill="#334155" font-size="11">    records_fetched / inserted / updated</text>
        <text x="15" y="170" fill="#334155" font-size="11">    error_message : TEXT</text>
    </g>

    <!-- Table 2: vulnerabilities -->
    <g transform="translate(390, 80)">
        <rect x="0" y="0" width="320" height="230" rx="6" fill="#ffffff" stroke="#2563eb" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="320" height="30" rx="6" fill="#1d4ed8" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">vulnerabilities</text>
        <text x="15" y="50" fill="#1d4ed8" font-size="11" font-weight="bold">PK  cve_id : VARCHAR(50)</text>
        <text x="15" y="70" fill="#334155" font-size="11">    description : TEXT</text>
        <text x="15" y="90" fill="#334155" font-size="11">    cvss_v3_score : FLOAT</text>
        <text x="15" y="110" fill="#334155" font-size="11">    cvss_v3_vector : VARCHAR(100)</text>
        <text x="15" y="130" fill="#334155" font-size="11">    cvss_v2_score : FLOAT</text>
        <text x="15" y="150" fill="#334155" font-size="11">    cvss_v2_vector : VARCHAR(100)</text>
        <text x="15" y="170" fill="#334155" font-size="11">    published_date : DATETIME</text>
        <text x="15" y="190" fill="#334155" font-size="11">    last_modified_date : DATETIME</text>
        <text x="15" y="210" fill="#334155" font-size="11">    created_at / updated_at : DATETIME</text>
    </g>

    <!-- Table 3: exploitation_status -->
    <g transform="translate(760, 80)">
        <rect x="0" y="0" width="310" height="190" rx="6" fill="#ffffff" stroke="#e11d48" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="310" height="30" rx="6" fill="#be123c" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">exploitation_status</text>
        <text x="15" y="50" fill="#be123c" font-size="11" font-weight="bold">PK,FK  cve_id : VARCHAR(50)</text>
        <text x="15" y="70" fill="#334155" font-size="11">    kev_flag : BOOLEAN (Default: False)</text>
        <text x="15" y="90" fill="#334155" font-size="11">    date_added : DATETIME</text>
        <text x="15" y="110" fill="#334155" font-size="11">    due_date : DATETIME</text>
        <text x="15" y="130" fill="#334155" font-size="11">    known_ransomware_campaign_use</text>
        <text x="15" y="150" fill="#334155" font-size="11">    notes : TEXT</text>
        <text x="15" y="170" fill="#334155" font-size="11">    updated_at : DATETIME</text>
    </g>

    <!-- Table 4: vulnerability_prioritizations -->
    <g transform="translate(390, 370)">
        <rect x="0" y="0" width="320" height="170" rx="6" fill="#ffffff" stroke="#d97706" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="320" height="30" rx="6" fill="#b45309" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">vulnerability_prioritizations</text>
        <text x="15" y="50" fill="#b45309" font-size="11" font-weight="bold">PK  priority_id : UUID</text>
        <text x="15" y="70" fill="#1d4ed8" font-size="11" font-weight="bold">FK  cve_id : VARCHAR(50)</text>
        <text x="15" y="90" fill="#334155" font-size="11">    priority_score : FLOAT (0.0 - 100.0)</text>
        <text x="15" y="110" fill="#334155" font-size="11">    priority_tier : VARCHAR(10) (P1-P4)</text>
        <text x="15" y="130" fill="#334155" font-size="11">    factor_breakdown : JSON / TEXT</text>
        <text x="15" y="150" fill="#334155" font-size="11">    created_at : DATETIME</text>
    </g>

    <!-- Table 5: organizations -->
    <g transform="translate(30, 480)">
        <rect x="0" y="0" width="300" height="170" rx="6" fill="#ffffff" stroke="#059669" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="300" height="30" rx="6" fill="#047857" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">organizations</text>
        <text x="15" y="50" fill="#047857" font-size="11" font-weight="bold">PK  organization_id : UUID</text>
        <text x="15" y="70" fill="#047857" font-size="11" font-weight="bold">UK  organization_ref : VARCHAR(100)</text>
        <text x="15" y="90" fill="#334155" font-size="11">    display_name : VARCHAR(255)</text>
        <text x="15" y="110" fill="#334155" font-size="11">    data_authorization_flag : BOOLEAN</text>
        <text x="15" y="130" fill="#334155" font-size="11">    created_at / updated_at : DATETIME</text>
    </g>

    <!-- Table 6: assets -->
    <g transform="translate(390, 580)">
        <rect x="0" y="0" width="320" height="180" rx="6" fill="#ffffff" stroke="#059669" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="320" height="30" rx="6" fill="#047857" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">assets</text>
        <text x="15" y="50" fill="#047857" font-size="11" font-weight="bold">PK  asset_id : UUID</text>
        <text x="15" y="70" fill="#047857" font-size="11" font-weight="bold">FK  organization_id : UUID</text>
        <text x="15" y="90" fill="#334155" font-size="11">    asset_ref : VARCHAR(100)</text>
        <text x="15" y="110" fill="#334155" font-size="11">    hostname / ip_address</text>
        <text x="15" y="130" fill="#334155" font-size="11">    asset_type : VARCHAR(50)</text>
        <text x="15" y="150" fill="#334155" font-size="11">    criticality : VARCHAR(20)</text>
        <text x="15" y="170" fill="#334155" font-size="11">    created_at / updated_at : DATETIME</text>
    </g>

    <!-- Table 7: vulnerability_observations -->
    <g transform="translate(760, 480)">
        <rect x="0" y="0" width="310" height="200" rx="6" fill="#ffffff" stroke="#7c3aed" stroke-width="1.5" filter="url(#shadow)" />
        <rect x="0" y="0" width="310" height="30" rx="6" fill="#6d28d9" />
        <text x="15" y="20" fill="#ffffff" font-size="12" font-weight="bold">vulnerability_observations</text>
        <text x="15" y="50" fill="#6d28d9" font-size="11" font-weight="bold">PK  observation_id : UUID</text>
        <text x="15" y="70" fill="#047857" font-size="11" font-weight="bold">FK  asset_id : UUID</text>
        <text x="15" y="90" fill="#1d4ed8" font-size="11" font-weight="bold">FK  cve_id : VARCHAR(50)</text>
        <text x="15" y="110" fill="#334155" font-size="11">    scanner_source : VARCHAR(100)</text>
        <text x="15" y="130" fill="#334155" font-size="11">    observed_at : DATETIME</text>
        <text x="15" y="150" fill="#334155" font-size="11">    status : VARCHAR(50) (VERIFIED, etc)</text>
        <text x="15" y="170" fill="#334155" font-size="11">    raw_evidence : JSON</text>
        <text x="15" y="190" fill="#334155" font-size="11">    created_at : DATETIME</text>
    </g>

    <!-- Relationships -->
    <!-- vulnerabilities <-> exploitation_status -->
    <path d="M 710 150 L 760 150" stroke="#be123c" stroke-width="2" marker-end="url(#arrow)" />
    <text x="735" y="140" fill="#be123c" font-size="10" font-weight="bold" text-anchor="middle">1 : 0..1</text>

    <!-- vulnerabilities <-> prioritizations -->
    <path d="M 550 310 L 550 370" stroke="#1d4ed8" stroke-width="2" marker-end="url(#arrow)" />
    <text x="565" y="340" fill="#1d4ed8" font-size="10" font-weight="bold">1 : 0..N</text>

    <!-- organizations <-> assets -->
    <path d="M 330 580 L 390 630" stroke="#047857" stroke-width="2" marker-end="url(#arrow)" />
    <text x="360" y="595" fill="#047857" font-size="10" font-weight="bold">1 : N</text>

    <!-- assets <-> observations -->
    <path d="M 710 650 L 760 620" stroke="#047857" stroke-width="2" marker-end="url(#arrow)" />
    <text x="735" y="625" fill="#047857" font-size="10" font-weight="bold">1 : N</text>

    <!-- vulnerabilities <-> observations -->
    <path d="M 680 310 Q 750 380 850 480" stroke="#1d4ed8" stroke-width="2" stroke-dasharray="4" marker-end="url(#arrow)" fill="none" />
    <text x="770" y="400" fill="#1d4ed8" font-size="10" font-weight="bold">1 : N (Ref)</text>
</svg>'''
    with open(os.path.join(out_dir, "figure_d_database_erd.svg"), "w", encoding="utf-8") as f:
        f.write(svg_d.strip())

    # =========================================================================
    # Figure E: Risk Scoring Flowchart
    # =========================================================================
    svg_e = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1050 720" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="1010" height="40" rx="6" fill="#1e293b" />
    <text x="525" y="41" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle">Figure 4.5: Explainable Organization-Level Cyber Risk Scoring Architecture</text>

    <!-- Enterprise Telemetry Inputs -->
    <rect x="40" y="75" width="970" height="70" rx="8" fill="url(#blueGrad)" stroke="#3b82f6" stroke-width="1.5" filter="url(#shadow)" />
    <text x="60" y="98" fill="#1e3a8a" font-size="13" font-weight="bold">VERIFIED ENTERPRISE SECURITY TELEMETRY INPUTS</text>
    
    <g transform="translate(60, 108)">
        <text x="0" y="20" fill="#1e293b" font-size="11" font-weight="600">1. MFA Enforced Pct (0-100%)</text>
        <text x="250" y="20" fill="#1e293b" font-size="11" font-weight="600">2. RDP Exposed to Internet (True/False)</text>
        <text x="550" y="20" fill="#1e293b" font-size="11" font-weight="600">3. Overdue Critical CVEs &gt; 30d (Count)</text>
        <text x="810" y="20" fill="#1e293b" font-size="11" font-weight="600">4. EDR Agent Coverage (0-100%)</text>
    </g>

    <path d="M 525 145 L 525 175" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

    <!-- Penalty Breakdown -->
    <rect x="40" y="175" width="970" height="150" rx="8" fill="url(#amberGrad)" stroke="#f59e0b" stroke-width="1.5" filter="url(#shadow)" />
    <text x="60" y="198" fill="#78350f" font-size="13" font-weight="bold">TRANSPARENT ADDITIVE PENALTY FORMULATIONS</text>

    <g transform="translate(60, 210)">
        <rect x="0" y="0" width="170" height="95" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="85" y="22" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Base Operational Risk</text>
        <text x="85" y="48" fill="#b45309" font-size="14" font-weight="bold" text-anchor="middle">R_base = 5.0</text>
        <text x="85" y="70" fill="#64748b" font-size="10" text-anchor="middle">Foundational baseline</text>
        <text x="85" y="85" fill="#047857" font-size="9" text-anchor="middle">+5.0 Fixed Floor</text>

        <rect x="190" y="0" width="180" height="95" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="280" y="22" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Weak MFA Penalty</text>
        <text x="280" y="48" fill="#b45309" font-size="12" font-weight="bold" text-anchor="middle">(100 - MFA) * 0.30</text>
        <text x="280" y="70" fill="#64748b" font-size="10" text-anchor="middle">Credential compromise</text>
        <text x="280" y="85" fill="#dc2626" font-size="9" font-weight="bold" text-anchor="middle">Max Penalty: +30.0</text>

        <rect x="390" y="0" width="180" height="95" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="480" y="22" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Exposed RDP Gateway</text>
        <text x="480" y="48" fill="#b45309" font-size="13" font-weight="bold" text-anchor="middle">25.0 if RDP else 0.0</text>
        <text x="480" y="70" fill="#64748b" font-size="10" text-anchor="middle">Ransomware initial vector</text>
        <text x="480" y="85" fill="#dc2626" font-size="9" font-weight="bold" text-anchor="middle">Penalty: +25.0</text>

        <rect x="590" y="0" width="180" height="95" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="680" y="22" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Overdue Critical CVEs</text>
        <text x="680" y="48" fill="#b45309" font-size="12" font-weight="bold" text-anchor="middle">min(35.0, CVEs * 7.0)</text>
        <text x="680" y="70" fill="#64748b" font-size="10" text-anchor="middle">Unpatched exploitable debt</text>
        <text x="680" y="85" fill="#dc2626" font-size="9" font-weight="bold" text-anchor="middle">Max Penalty: +35.0</text>

        <rect x="790" y="0" width="160" height="95" rx="6" fill="#ffffff" stroke="#fcd34d" />
        <text x="870" y="22" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Low EDR Coverage</text>
        <text x="870" y="48" fill="#b45309" font-size="12" font-weight="bold" text-anchor="middle">(100 - EDR) * 0.20</text>
        <text x="870" y="70" fill="#64748b" font-size="10" text-anchor="middle">Endpoint blind spots</text>
        <text x="870" y="85" fill="#dc2626" font-size="9" font-weight="bold" text-anchor="middle">Max Penalty: +20.0</text>
    </g>

    <path d="M 525 325 L 525 355" stroke="#475569" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Clamping & Normalization Box -->
    <rect x="225" y="355" width="600" height="50" rx="6" fill="#1e293b" filter="url(#shadow)" />
    <text x="525" y="375" fill="#ffffff" font-size="11" font-weight="bold" text-anchor="middle">MATHEMATICAL CLAMPING &amp; COMPOSITE AGGREGATION</text>
    <text x="525" y="393" fill="#38bdf8" font-size="11" font-family="monospace" font-weight="bold" text-anchor="middle">FinalScore = min(100.0, max(0.0, R_base + P_MFA + P_RDP + P_CVE + P_EDR))</text>

    <path d="M 525 405 L 525 435" stroke="#475569" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Tiers & Policy Actions -->
    <g transform="translate(40, 435)">
        <!-- Low -->
        <rect x="0" y="0" width="230" height="135" rx="6" fill="#ecfdf5" stroke="#10b981" stroke-width="1.5" />
        <text x="115" y="24" fill="#065f46" font-size="13" font-weight="bold" text-anchor="middle">LOW RISK TIER</text>
        <text x="115" y="42" fill="#047857" font-size="11" font-weight="bold" text-anchor="middle">Score &lt; 40.0</text>
        <text x="115" y="62" fill="#334155" font-size="10" text-anchor="middle">Minimal residual technical risk</text>
        <rect x="15" y="75" width="200" height="45" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="115" y="93" fill="#047857" font-size="10" font-weight="bold" text-anchor="middle">Policy Action: NOMINAL</text>
        <text x="115" y="108" fill="#64748b" font-size="9" text-anchor="middle">Bind standard terms &amp; deductible</text>

        <!-- Medium -->
        <rect x="245" y="0" width="230" height="135" rx="6" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.5" />
        <text x="360" y="24" fill="#1e40af" font-size="13" font-weight="bold" text-anchor="middle">MEDIUM RISK TIER</text>
        <text x="360" y="42" fill="#1d4ed8" font-size="11" font-weight="bold" text-anchor="middle">40.0 &lt;= Score &lt; 60.0</text>
        <text x="360" y="62" fill="#334155" font-size="10" text-anchor="middle">Moderate security deficiencies</text>
        <rect x="260" y="75" width="200" height="45" rx="4" fill="#ffffff" stroke="#bfdbfe" />
        <text x="360" y="93" fill="#1d4ed8" font-size="10" font-weight="bold" text-anchor="middle">Policy Action: MONITOR</text>
        <text x="360" y="108" fill="#64748b" font-size="9" text-anchor="middle">Bind with 60-day telemetry check</text>

        <!-- High -->
        <rect x="490" y="0" width="230" height="135" rx="6" fill="#fff7ed" stroke="#f97316" stroke-width="1.5" />
        <text x="605" y="24" fill="#9a3412" font-size="13" font-weight="bold" text-anchor="middle">HIGH RISK TIER</text>
        <text x="605" y="42" fill="#c2410c" font-size="11" font-weight="bold" text-anchor="middle">60.0 &lt;= Score &lt; 80.0</text>
        <text x="605" y="62" fill="#334155" font-size="10" text-anchor="middle">Severe control vulnerabilities</text>
        <rect x="505" y="75" width="200" height="45" rx="4" fill="#ffffff" stroke="#fed7aa" />
        <text x="605" y="93" fill="#c2410c" font-size="10" font-weight="bold" text-anchor="middle">Action: REVIEW REQUIRED</text>
        <text x="605" y="108" fill="#64748b" font-size="9" text-anchor="middle">Refer to senior underwriter</text>

        <!-- Critical -->
        <rect x="735" y="0" width="235" height="135" rx="6" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5" />
        <text x="852" y="24" fill="#991b1b" font-size="13" font-weight="bold" text-anchor="middle">CRITICAL RISK TIER</text>
        <text x="852" y="42" fill="#b91c1c" font-size="11" font-weight="bold" text-anchor="middle">Score &gt;= 80.0</text>
        <text x="852" y="62" fill="#334155" font-size="10" text-anchor="middle">Extreme threat exposure</text>
        <rect x="750" y="75" width="205" height="45" rx="4" fill="#ffffff" stroke="#fecaca" />
        <text x="852" y="93" fill="#b91c1c" font-size="10" font-weight="bold" text-anchor="middle">Action: REVIEW REQUIRED</text>
        <text x="852" y="108" fill="#64748b" font-size="9" text-anchor="middle">Decline coverage or warranty</text>
    </g>

    <!-- Predefined Scenarios Evaluation -->
    <rect x="40" y="585" width="970" height="110" rx="8" fill="#f8fafc" stroke="#cbd5e1" filter="url(#shadow)" />
    <text x="60" y="608" fill="#0f172a" font-size="12" font-weight="bold">VERIFIED PREDEFINED SCENARIO EXECUTION BENCHMARKS</text>
    
    <g transform="translate(60, 620)">
        <rect x="0" y="0" width="300" height="60" rx="4" fill="#ffffff" stroke="#e2e8f0" />
        <text x="15" y="20" fill="#047857" font-size="11" font-weight="bold">Scenario A: Clean Enterprise (Apex Financial)</text>
        <text x="15" y="36" fill="#64748b" font-size="10">MFA 100%, RDP Closed, CVE 0, EDR 100%</text>
        <text x="15" y="52" fill="#047857" font-size="10" font-weight="bold">Risk Score = 5.0 | Tier = LOW | Action = NOMINAL</text>

        <rect x="325" y="0" width="300" height="60" rx="4" fill="#ffffff" stroke="#e2e8f0" />
        <text x="15" y="20" fill="#1d4ed8" font-size="11" font-weight="bold">Scenario B: Moderate Risk (Meridian Health)</text>
        <text x="15" y="36" fill="#64748b" font-size="10">MFA 80%, RDP Closed, CVE 2, EDR 70%</text>
        <text x="15" y="52" fill="#1d4ed8" font-size="10" font-weight="bold">Risk Score = 31.0 | Tier = LOW | Action = NOMINAL</text>

        <rect x="650" y="0" width="300" height="60" rx="4" fill="#ffffff" stroke="#e2e8f0" />
        <text x="15" y="20" fill="#b91c1c" font-size="11" font-weight="bold">Scenario C: Severe Compromise (Titan Logistics)</text>
        <text x="15" y="36" fill="#64748b" font-size="10">MFA 20%, RDP Exposed, CVE 6, EDR 30%</text>
        <text x="15" y="52" fill="#b91c1c" font-size="10" font-weight="bold">Risk Score = 95.0 | Tier = CRITICAL | REVIEW_REQ</text>
    </g>
</svg>'''
    with open(os.path.join(out_dir, "figure_e_risk_scoring_flowchart.svg"), "w", encoding="utf-8") as f:
        f.write(svg_e.strip())

    # =========================================================================
    # Figure F: Asset Observation Lifecycle
    # =========================================================================
    svg_f = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 680" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="960" height="40" rx="6" fill="#1e293b" />
    <text x="500" y="41" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle">Figure 4.6: Enterprise Asset Governance &amp; Vulnerability Observation Lifecycle</text>

    <!-- Phase 1: Org Onboarding -->
    <g transform="translate(50, 75)">
        <rect x="0" y="0" width="900" height="80" rx="6" fill="url(#emeraldGrad)" stroke="#10b981" stroke-width="1.5" filter="url(#shadow)" />
        <text x="20" y="25" fill="#065f46" font-size="13" font-weight="bold">PHASE 1: ORGANIZATION ONBOARDING &amp; LEGAL DATA CONSENT</text>
        <rect x="20" y="35" width="380" height="32" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="30" y="55" fill="#1e293b" font-size="11">POST /api/v1/organizations (organization_ref, display_name)</text>
        <rect x="420" y="35" width="450" height="32" rx="4" fill="#ffffff" stroke="#a7f3d0" />
        <text x="430" y="55" fill="#047857" font-size="11" font-weight="bold">Verification Gate: data_authorization_flag == True (Legal Authorization)</text>
    </g>

    <path d="M 500 155 L 500 185" stroke="#059669" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Phase 2: Asset Inventory -->
    <g transform="translate(50, 185)">
        <rect x="0" y="0" width="900" height="80" rx="6" fill="url(#blueGrad)" stroke="#3b82f6" stroke-width="1.5" filter="url(#shadow)" />
        <text x="20" y="25" fill="#1e3a8a" font-size="13" font-weight="bold">PHASE 2: ENTERPRISE ASSET INVENTORY REGISTRATION</text>
        <rect x="20" y="35" width="420" height="32" rx="4" fill="#ffffff" stroke="#93c5fd" />
        <text x="30" y="55" fill="#1e293b" font-size="11">Register Infrastructure: Hostnames, IP Addresses, Asset Types</text>
        <rect x="460" y="35" width="410" height="32" rx="4" fill="#ffffff" stroke="#93c5fd" />
        <text x="470" y="55" fill="#1e3a8a" font-size="11" font-weight="bold">Assign Criticality Tier: LOW, MEDIUM, HIGH, CRITICAL</text>
    </g>

    <path d="M 500 265 L 500 295" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

    <!-- Phase 3: Scanner Ingestion -->
    <g transform="translate(50, 295)">
        <rect x="0" y="0" width="900" height="85" rx="6" fill="url(#purpleGrad)" stroke="#8b5cf6" stroke-width="1.5" filter="url(#shadow)" />
        <text x="20" y="25" fill="#581c87" font-size="13" font-weight="bold">PHASE 3: SCANNER FINDING INGESTION (QUALYS / TENABLE / NESSUS)</text>
        <rect x="20" y="35" width="420" height="38" rx="4" fill="#ffffff" stroke="#c4b5fd" />
        <text x="30" y="53" fill="#1e293b" font-size="10">Validate Asset Association: asset_ref mapped to parent org</text>
        <text x="30" y="66" fill="#64748b" font-size="9">Rejects orphan findings to maintain data isolation</text>
        <rect x="460" y="35" width="410" height="38" rx="4" fill="#ffffff" stroke="#c4b5fd" />
        <text x="470" y="53" fill="#581c87" font-size="10" font-weight="bold">Extract Finding Attributes: CVE ID, scanner_source, observed_at</text>
        <text x="470" y="66" fill="#64748b" font-size="9">Preserves raw scanner payload in raw_evidence JSON column</text>
    </g>

    <path d="M 500 380 L 500 410" stroke="#7c3aed" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Phase 4: Threat Intelligence Enrichment -->
    <g transform="translate(50, 410)">
        <rect x="0" y="0" width="900" height="85" rx="6" fill="url(#amberGrad)" stroke="#f59e0b" stroke-width="1.5" filter="url(#shadow)" />
        <text x="20" y="25" fill="#78350f" font-size="13" font-weight="bold">PHASE 4: RELATIONAL THREAT INTELLIGENCE JOINING</text>
        <rect x="20" y="35" width="420" height="38" rx="4" fill="#ffffff" stroke="#fcd34d" />
        <text x="30" y="53" fill="#1e293b" font-size="10">Join 'vulnerabilities' table: Attach CVSS v3.1 metrics &amp; vectors</text>
        <text x="30" y="66" fill="#64748b" font-size="9">Enriches finding with authoritative NIST descriptions</text>
        <rect x="460" y="35" width="410" height="38" rx="4" fill="#ffffff" stroke="#fcd34d" />
        <text x="470" y="53" fill="#b45309" font-size="10" font-weight="bold">Join 'exploitation_status' table: Attach CISA KEV flag &amp; ransomware</text>
        <text x="470" y="66" fill="#64748b" font-size="9">Flags whether observation represents an actively weaponized exploit</text>
    </g>

    <path d="M 500 495 L 500 525" stroke="#b45309" stroke-width="2" marker-end="url(#arrow)" />

    <!-- Phase 5: Triage & Underwriting Integration -->
    <g transform="translate(50, 525)">
        <rect x="0" y="0" width="900" height="120" rx="6" fill="#f8fafc" stroke="#64748b" stroke-width="1.5" filter="url(#shadow)" />
        <text x="20" y="25" fill="#0f172a" font-size="13" font-weight="bold">PHASE 5: FINDING TRIAGE &amp; UNDERWRITING RISK EVALUATION</text>
        
        <rect x="20" y="38" width="260" height="65" rx="4" fill="#ffffff" stroke="#cbd5e1" />
        <text x="150" y="58" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Status: VERIFIED</text>
        <text x="150" y="74" fill="#64748b" font-size="10" text-anchor="middle">Scanner confirmed vulnerable asset</text>
        <text x="150" y="90" fill="#dc2626" font-size="9" font-weight="bold" text-anchor="middle">Feeds into RiskEngine Penalty</text>

        <rect x="310" y="38" width="260" height="65" rx="4" fill="#ffffff" stroke="#cbd5e1" />
        <text x="440" y="58" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Status: UNVERIFIED / FALSE +</text>
        <text x="440" y="74" fill="#64748b" font-size="10" text-anchor="middle">Awaiting manual security review</text>
        <text x="440" y="90" fill="#d97706" font-size="9" font-weight="bold" text-anchor="middle">Excluded from Underwriting Penalty</text>

        <rect x="600" y="38" width="280" height="65" rx="4" fill="#ffffff" stroke="#cbd5e1" />
        <text x="740" y="58" fill="#1e293b" font-size="11" font-weight="bold" text-anchor="middle">Status: REMEDIATED</text>
        <text x="740" y="74" fill="#64748b" font-size="10" text-anchor="middle">Patch applied &amp; re-scan confirmed</text>
        <text x="740" y="90" fill="#059669" font-size="9" font-weight="bold" text-anchor="middle">Reduces Overdue CVE Penalty to 0</text>
    </g>
</svg>'''
    with open(os.path.join(out_dir, "figure_f_asset_observation_lifecycle.svg"), "w", encoding="utf-8") as f:
        f.write(svg_f.strip())

    # =========================================================================
    # Figure G: Testing Framework
    # =========================================================================
    svg_g = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 680" width="100%" height="100%" style="background:#ffffff; font-family:'Segoe UI', Inter, Arial, sans-serif;">
    {defs}
    <!-- Title -->
    <rect x="20" y="15" width="960" height="40" rx="6" fill="#1e293b" />
    <text x="500" y="41" fill="#ffffff" font-size="16" font-weight="bold" text-anchor="middle">Figure 5.1: Multi-Layer Automated Verification &amp; Quality Assurance Framework</text>

    <!-- Top Summary Banner -->
    <rect x="40" y="70" width="920" height="50" rx="6" fill="#ecfdf5" stroke="#10b981" stroke-width="1.5" />
    <text x="500" y="100" fill="#065f46" font-size="13" font-weight="bold" text-anchor="middle">EMPIRICAL TEST EXECUTION RESULT: 94 TOTAL AUTOMATED TESTS PASSING (100% SUCCESS RATE)</text>

    <!-- Left Box: Backend Pytest (77 Tests) -->
    <rect x="40" y="135" width="445" height="400" rx="8" fill="url(#blueGrad)" stroke="#3b82f6" stroke-width="1.5" filter="url(#shadow)" />
    <rect x="40" y="135" width="445" height="35" rx="8" fill="#1d4ed8" />
    <text x="55" y="158" fill="#ffffff" font-size="13" font-weight="bold">BACKEND PYTEST TEST HARNESS (77 Tests Passing)</text>
    <text x="465" y="158" fill="#a7f3d0" font-size="11" font-weight="bold" text-anchor="end">100% PASS (5.45s)</text>

    <g transform="translate(55, 185)">
        <rect x="0" y="0" width="415" height="48" rx="4" fill="#ffffff" stroke="#bfdbfe" />
        <text x="10" y="18" fill="#1e3a8a" font-size="11" font-weight="bold">Prioritization Engine Tests (16 Tests)</text>
        <text x="10" y="34" fill="#64748b" font-size="9">P1-P4 rule thresholds, KEV (+30), Ransomware (+15), Clamping [0, 100]</text>

        <rect x="0" y="56" width="415" height="48" rx="4" fill="#ffffff" stroke="#bfdbfe" />
        <text x="10" y="74" fill="#1e3a8a" font-size="11" font-weight="bold">Threat Ingestion Pipelines (18 Tests)</text>
        <text x="10" y="90" fill="#64748b" font-size="9">NVD targeted &amp; paginated ingestion, CISA KEV parsing, HTTP 429 resilience</text>

        <rect x="0" y="112" width="415" height="48" rx="4" fill="#ffffff" stroke="#bfdbfe" />
        <text x="10" y="130" fill="#1e3a8a" font-size="11" font-weight="bold">Organizations &amp; Assets API (15 Tests)</text>
        <text x="10" y="146" fill="#64748b" font-size="9">CRUD, legal consent enforcement, unique org_ref UK, FK cascades</text>

        <rect x="0" y="168" width="415" height="48" rx="4" fill="#ffffff" stroke="#bfdbfe" />
        <text x="10" y="186" fill="#1e3a8a" font-size="11" font-weight="bold">Vulnerability Observations API (14 Tests)</text>
        <text x="10" y="202" fill="#64748b" font-size="9">Scanner finding ingestion, asset-cve mapping, status updates</text>

        <rect x="0" y="224" width="415" height="48" rx="4" fill="#ffffff" stroke="#bfdbfe" />
        <text x="10" y="242" fill="#1e3a8a" font-size="11" font-weight="bold">RiskEngine &amp; Underwriting Gateway (14 Tests)</text>
        <text x="10" y="258" fill="#64748b" font-size="9">Scenarios A/B/C verification, Guidewire mock note/activity payload generation</text>

        <rect x="0" y="280" width="415" height="50" rx="4" fill="#f0fdf4" stroke="#86efac" />
        <text x="10" y="298" fill="#166534" font-size="11" font-weight="bold">Isolated In-Memory Fixtures</text>
        <text x="10" y="314" fill="#166534" font-size="9">sqlite:///:memory: database per test session; zero external network calls</text>
    </g>

    <!-- Right Box: Frontend Vitest & Build (17 Tests) -->
    <rect x="515" y="135" width="445" height="400" rx="8" fill="url(#purpleGrad)" stroke="#8b5cf6" stroke-width="1.5" filter="url(#shadow)" />
    <rect x="515" y="135" width="445" height="35" rx="8" fill="#6d28d9" />
    <text x="530" y="158" fill="#ffffff" font-size="13" font-weight="bold">FRONTEND VITEST &amp; BUILD HARNESS (17 Tests)</text>
    <text x="940" y="158" fill="#a7f3d0" font-size="11" font-weight="bold" text-anchor="end">100% PASS (6.06s)</text>

    <g transform="translate(530, 185)">
        <rect x="0" y="0" width="415" height="48" rx="4" fill="#ffffff" stroke="#ddd6fe" />
        <text x="10" y="18" fill="#581c87" font-size="11" font-weight="bold">Overview Page Component Tests (5 Tests)</text>
        <text x="10" y="34" fill="#64748b" font-size="9">Total CVE, KEV, P1-P4 metric card rendering, sync status cards</text>

        <rect x="0" y="56" width="415" height="48" rx="4" fill="#ffffff" stroke="#ddd6fe" />
        <text x="10" y="74" fill="#581c87" font-size="11" font-weight="bold">Explorer Page Component Tests (4 Tests)</text>
        <text x="10" y="90" fill="#64748b" font-size="9">CVE search debouncing, KEV badge display, priority factor drawer</text>

        <rect x="0" y="112" width="415" height="48" rx="4" fill="#ffffff" stroke="#ddd6fe" />
        <text x="10" y="130" fill="#581c87" font-size="11" font-weight="bold">Prioritization Config Tests (4 Tests)</text>
        <text x="10" y="146" fill="#64748b" font-size="9">Threshold slider inputs, weight configuration validation form</text>

        <rect x="0" y="168" width="415" height="48" rx="4" fill="#ffffff" stroke="#ddd6fe" />
        <text x="10" y="186" fill="#581c87" font-size="11" font-weight="bold">Observed Vulnerabilities Tests (4 Tests)</text>
        <text x="10" y="202" fill="#64748b" font-size="9">Enterprise findings table, asset filtering, status triage buttons</text>

        <rect x="0" y="224" width="415" height="48" rx="4" fill="#ffffff" stroke="#ddd6fe" />
        <text x="10" y="242" fill="#581c87" font-size="11" font-weight="bold">TypeScript Static Typecheck (tsc --noEmit)</text>
        <text x="10" y="258" fill="#047857" font-size="9" font-weight="bold">Zero compile-time type errors across all interfaces &amp; API schemas</text>

        <rect x="0" y="280" width="415" height="50" rx="4" fill="#f0fdf4" stroke="#86efac" />
        <text x="10" y="298" fill="#166534" font-size="11" font-weight="bold">Vite Production Bundle Verification</text>
        <text x="10" y="314" fill="#166534" font-size="9">Compiled 100% cleanly in 563 ms; assets minified and tree-shaken</text>
    </g>

    <!-- Bottom Test Execution Matrix -->
    <rect x="40" y="550" width="920" height="105" rx="8" fill="#1e293b" filter="url(#shadow)" />
    <text x="60" y="575" fill="#ffffff" font-size="12" font-weight="bold">CONTINUOUS INTEGRATION &amp; TEST ENVIRONMENT SPECIFICATIONS</text>
    
    <g transform="translate(60, 585)">
        <text x="0" y="20" fill="#94a3b8" font-size="10">Test Engine: Pytest 8.3.4 + Vitest 3.0.4</text>
        <text x="250" y="20" fill="#94a3b8" font-size="10">Database: In-Memory SQLite 3 (Isolated)</text>
        <text x="560" y="20" fill="#94a3b8" font-size="10">HTTP Fixtures: Unittest Mock AsyncClient</text>
        <text x="800" y="20" fill="#4ade80" font-size="10" font-weight="bold">Status: ALL PASS</text>

        <text x="0" y="42" fill="#94a3b8" font-size="10">UI Harness: React Testing Library + JSDOM</text>
        <text x="250" y="42" fill="#94a3b8" font-size="10">Bundle Speed: 563 ms (Vite 6.0.7)</text>
        <text x="560" y="42" fill="#94a3b8" font-size="10">Coverage: Prioritization, Ingestion, Risk</text>
        <text x="800" y="42" fill="#4ade80" font-size="10" font-weight="bold">Exit Code: 0</text>
    </g>
</svg>'''
    with open(os.path.join(out_dir, "figure_g_testing_framework.svg"), "w", encoding="utf-8") as f:
        f.write(svg_g.strip())

    print("All 7 publication SVG diagrams successfully generated in", out_dir)

if __name__ == "__main__":
    create_svgs()

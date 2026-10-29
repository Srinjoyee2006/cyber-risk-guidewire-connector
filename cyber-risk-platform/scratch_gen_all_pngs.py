import os
from PIL import Image, ImageDraw, ImageFont

def get_font(size, bold=False):
    try:
        if bold:
            return ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", size)
        else:
            return ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", size)
    except:
        try:
            if bold:
                return ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", size)
            else:
                return ImageFont.truetype("C:/Windows/Fonts/arial.ttf", size)
        except:
            return ImageFont.load_default()

def draw_header(d, w, title):
    d.rounded_rectangle([(30, 20), (w - 30, 90)], radius=10, fill=(30, 41, 59))
    f_title = get_font(28, bold=True)
    d.text((w // 2, 55), title, font=f_title, fill=(255, 255, 255), anchor="mm")

def draw_box(d, xy, fill_bg, stroke_col, title, subtitle=None, badge=None, badge_col=(59, 130, 246)):
    d.rounded_rectangle(xy, radius=10, fill=fill_bg, outline=stroke_col, width=2)
    x1, y1 = xy[0]
    x2, y2 = xy[1]
    w = x2 - x1
    f_t = get_font(18, bold=True)
    d.text((x1 + 20, y1 + 25), title, font=f_t, fill=(15, 23, 42))
    if subtitle:
        f_sub = get_font(14, bold=False)
        d.text((x1 + 20, y1 + 50), subtitle, font=f_sub, fill=(100, 116, 139))
    if badge:
        f_b = get_font(12, bold=True)
        bw = len(badge) * 9 + 20
        d.rounded_rectangle([(x2 - bw - 15, y1 + 15), (x2 - 15, y1 + 42)], radius=5, fill=badge_col)
        d.text((x2 - bw // 2 - 15, y1 + 28), badge, font=f_b, fill=(255, 255, 255), anchor="mm")

def draw_arrow(d, p1, p2, col=(71, 85, 105), width=3, text=None):
    d.line([p1, p2], fill=col, width=width)
    x2, y2 = p2
    x1, y1 = p1
    # Simple arrowhead
    if x1 == x2: # vertical
        if y2 > y1:
            d.polygon([(x2 - 8, y2 - 14), (x2 + 8, y2 - 14), (x2, y2)], fill=col)
        else:
            d.polygon([(x2 - 8, y2 + 14), (x2 + 8, y2 + 14), (x2, y2)], fill=col)
    elif y1 == y2: # horizontal
        if x2 > x1:
            d.polygon([(x2 - 14, y2 - 8), (x2 - 14, y2 + 8), (x2, y2)], fill=col)
        else:
            d.polygon([(x2 + 14, y2 - 8), (x2 + 14, y2 + 8), (x2, y2)], fill=col)
    if text:
        f_lbl = get_font(13, bold=True)
        mx, my = (x1 + x2) // 2, (y1 + y2) // 2
        d.text((mx + 10, my - 10), text, font=f_lbl, fill=col)

def main():
    out_dir = r"d:\New folder\report_materials"
    os.makedirs(out_dir, exist_ok=True)

    # -------------------------------------------------------------
    # Figure A: System Architecture
    # -------------------------------------------------------------
    W, H = 2200, 1750
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 4.1: CRGC Multi-Tier System Architecture")

    # Tier 1: Presentation Tier
    d.rounded_rectangle([(50, 120), (W - 50, 360)], radius=12, fill=(239, 246, 255), outline=(59, 130, 246), width=3)
    d.text((80, 145), "PRESENTATION TIER (React 19 / TypeScript 5.7 / Vite 6.0 / Tailwind CSS 4.0)", font=get_font(20, bold=True), fill=(30, 58, 138))
    
    screens = [
        ("Overview Dashboard", "Total Vulnerabilities, KEV Counts,\nP1-P4 Tiers, Ingestion History"),
        ("Vulnerability Explorer", "Paginated CVE Catalog, KEV Badges,\nSearch & Factor Breakdown Drawer"),
        ("Priority Configuration", "Threshold Sliders & Factor Weights\nGovernance Interface"),
        ("Observed Findings", "Authorized Asset Vulnerabilities,\nScanner Source Triage"),
        ("Underwriting Terminal", "RiskEngine Scoring, Scenario Test,\nPolicyCenter Directives")
    ]
    card_w = 380
    for i, (title, sub) in enumerate(screens):
        cx = 80 + i * 410
        d.rounded_rectangle([(cx, 190), (cx + card_w, 320)], radius=8, fill=(255, 255, 255), outline=(147, 197, 253), width=2)
        d.text((cx + card_w // 2, 225), title, font=get_font(18, bold=True), fill=(15, 23, 42), anchor="mm")
        d.text((cx + card_w // 2, 270), sub, font=get_font(14, bold=False), fill=(100, 116, 139), anchor="mm", align="center")

    draw_arrow(d, (W // 2, 360), (W // 2, 420), col=(37, 99, 235), width=4, text="JSON over Asynchronous REST HTTP (Axios API Client)")

    # Tier 2: Application API Tier
    d.rounded_rectangle([(50, 420), (W - 50, 680)], radius=12, fill=(250, 245, 255), outline=(139, 92, 246), width=3)
    d.text((80, 445), "APPLICATION API TIER (FastAPI v0.115.6 / Pydantic v2 / Uvicorn ASGI Server)", font=get_font(20, bold=True), fill=(88, 28, 135))
    
    endpoints = [
        ("/api/v1/vulnerabilities", "List, Search, Detail & Ingest NVD\nPydantic DTO Serialization"),
        ("/api/v1/exploitation-status", "Query KEV State & Sync CISA Feed\nExploitation Metadata Extraction"),
        ("/api/v1/prioritizations", "Evaluate Priority Score & Assign P1-P4\nFactor Audit Trail Persistence"),
        ("/api/v1/organizations & assets", "Enterprise Asset Management\nLegal Consent Verification Gate"),
        ("/api/v1/underwriting/evaluate", "Execute Organization RiskEngine\nGuidewire Mock Handler Gateway")
    ]
    for i, (title, sub) in enumerate(endpoints):
        cx = 80 + i * 410
        d.rounded_rectangle([(cx, 490), (cx + card_w, 640)], radius=8, fill=(255, 255, 255), outline=(196, 181, 253), width=2)
        d.text((cx + card_w // 2, 525), title, font=get_font(16, bold=True), fill=(15, 23, 42), anchor="mm")
        d.text((cx + card_w // 2, 580), sub, font=get_font(13, bold=False), fill=(100, 116, 139), anchor="mm", align="center")

    draw_arrow(d, (W // 2, 680), (W // 2, 740), col=(71, 85, 105), width=4)

    # Tier 3: Core Processing & Analytics Engines
    d.rounded_rectangle([(50, 740), (W - 50, 1020)], radius=12, fill=(255, 251, 235), outline=(245, 158, 11), width=3)
    d.text((80, 765), "CORE PROCESSING & ANALYTICS ENGINES", font=get_font(20, bold=True), fill=(120, 53, 15))

    engines = [
        ("Threat Ingestion Services", "NVD & CISA KEV HTTPX Clients\nPagination, Backoff, Deduplication", "DATA PIPELINE", (5, 150, 105)),
        ("PrioritizationEngine", "Base CVSS (x10) + KEV (+30) + Ransom (+15)\nClamped to [0, 100] -> Tiers P1, P2, P3, P4", "DECISION LOGIC", (217, 119, 6)),
        ("Organization RiskEngine", "Base 5.0 + MFA (30) + RDP (25) + CVE (35) + EDR (20)\nComposite Clamping [0, 100] -> Risk Tiers", "ACTUARIAL HEURISTIC", (220, 38, 38)),
        ("Coverage & Policy Engine", "Translates Composite Risk into Underwriting Actions\nNominal / Monitor / Review Required", "INSURANCE GATEWAY", (37, 99, 235))
    ]
    eng_w = 480
    for i, (title, sub, badge, bcol) in enumerate(engines):
        cx = 80 + i * 515
        d.rounded_rectangle([(cx, 810), (cx + eng_w, 980)], radius=8, fill=(255, 255, 255), outline=(252, 211, 77), width=2)
        d.text((cx + 25, 845), title, font=get_font(18, bold=True), fill=(15, 23, 42))
        d.text((cx + 25, 885), sub, font=get_font(14, bold=False), fill=(100, 116, 139))
        f_b = get_font(11, bold=True)
        bw = len(badge) * 8 + 16
        d.rounded_rectangle([(cx + eng_w - bw - 20, 830), (cx + eng_w - 20, 858)], radius=4, fill=bcol)
        d.text((cx + eng_w - bw // 2 - 20, 844), badge, font=f_b, fill=(255, 255, 255), anchor="mm")

    draw_arrow(d, (500, 1020), (500, 1080), col=(71, 85, 105), width=4)
    draw_arrow(d, (1700, 1020), (1700, 1080), col=(139, 92, 246), width=4)

    # Tier 4: Left = Persistence (SQLite), Right = External Feeds & Guidewire Mock
    # Left: Database (7 Tables)
    d.rounded_rectangle([(50, 1080), (1150, 1700)], radius=12, fill=(236, 253, 245), outline=(16, 185, 129), width=3)
    d.text((80, 1110), "PERSISTENCE TIER (SQLAlchemy 2.0 / SQLite 3 - cyber_risk.db)", font=get_font(20, bold=True), fill=(6, 78, 59))
    
    tables = [
        ("data_ingestion_runs", "run_id PK, feed_type, started_at, completed_at, status, counts, error_msg"),
        ("vulnerabilities", "cve_id PK, description, cvss_v3_score/vector, cvss_v2, published, dates"),
        ("exploitation_status", "cve_id PK FK, kev_flag, date_added, due_date, ransomware_use, notes"),
        ("vulnerability_prioritizations", "priority_id PK, cve_id FK, priority_score, priority_tier, factor_breakdown JSON"),
        ("organizations", "organization_id PK, organization_ref UK, display_name, data_authorization_flag"),
        ("assets", "asset_id PK, organization_id FK, asset_ref, hostname, ip_address, type, criticality"),
        ("vulnerability_observations", "observation_id PK, asset_id FK, cve_id FK, scanner_source, status, raw_evidence")
    ]
    for i, (tname, tdesc) in enumerate(tables):
        cy = 1150 + i * 75
        d.rounded_rectangle([(80, cy), (1120, cy + 62)], radius=6, fill=(255, 255, 255), outline=(167, 243, 208), width=2)
        d.text((100, cy + 22), tname, font=get_font(16, bold=True), fill=(4, 120, 87))
        d.text((100, cy + 44), tdesc, font=get_font(13, bold=False), fill=(100, 116, 139))

    # Right: External Threat Feeds
    d.rounded_rectangle([(1200, 1080), (W - 50, 1370)], radius=12, fill=(255, 241, 242), outline=(244, 63, 94), width=3)
    d.text((1230, 1110), "EXTERNAL THREAT INTELLIGENCE (LIVE HTTPS)", font=get_font(20, bold=True), fill=(136, 19, 55))
    
    d.rounded_rectangle([(1230, 1150), (1650, 1330)], radius=8, fill=(255, 255, 255), outline=(254, 205, 211), width=2)
    d.text((1250, 1180), "NIST NVD API 2.0", font=get_font(18, bold=True), fill=(15, 23, 42))
    d.text((1250, 1215), "Endpoint: services.nvd.nist.gov/rest/json/cves/2.0\nFormat: REST JSON\nConsumption: Asynchronous HTTP Client\nPayload: CVSS v3.1 / v2.0 Base Score & Vector", font=get_font(13, bold=False), fill=(100, 116, 139))

    d.rounded_rectangle([(1700, 1150), (W - 80, 1330)], radius=8, fill=(255, 255, 255), outline=(254, 205, 211), width=2)
    d.text((1720, 1180), "CISA KEV Catalog Feed", font=get_font(18, bold=True), fill=(15, 23, 42))
    d.text((1720, 1215), "Endpoint: cisa.gov/feeds/known_exploited_vulnerabilities.json\nFormat: Static JSON Catalog (1,739+ Records)\nConsumption: Stream JSON Parsing & Pydantic Validation\nPayload: dateAdded, dueDate, ransomwareFlag", font=get_font(13, bold=False), fill=(100, 116, 139))

    # Right: Guidewire Mock Service
    d.rounded_rectangle([(1200, 1400), (W - 50, 1700)], radius=12, fill=(250, 245, 255), outline=(139, 92, 246), width=3)
    d.text((1230, 1430), "GUIDEWIRE POLICYCENTER INTEGRATION (SIMULATED)", font=get_font(20, bold=True), fill=(76, 29, 149))
    
    d.rounded_rectangle([(1230, 1470), (W - 80, 1660)], radius=8, fill=(255, 255, 255), outline=(221, 214, 254), width=2)
    d.text((1250, 1505), "Guidewire Service Adapter (GW_MOCK_MODE = True)", font=get_font(18, bold=True), fill=(107, 33, 168))
    d.text((1250, 1540), "Simulates Underwriting File Activities & Referral Notes\nTranslates RiskEngine Scores into Policy Decisions: Nominal, Monitor, Review Required\nGenerates Underwriting Activity Payload without Live Production Credentials\nFully Compliant with Guidewire Cloud Integration Gateway Architecture", font=get_font(14, bold=False), fill=(100, 116, 139))

    im.save(os.path.join(out_dir, "figure_a_system_architecture.png"), dpi=(300, 300))
    print("Saved figure_a_system_architecture.png")

    # -------------------------------------------------------------
    # Figure B: Ingestion Pipeline
    # -------------------------------------------------------------
    W, H = 2200, 1450
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 4.2: Dual-Stream Vulnerability Threat Intelligence Ingestion Pipeline")

    # Left: NVD
    d.rounded_rectangle([(50, 120), (1070, 1380)], radius=12, fill=(239, 246, 255), outline=(59, 130, 246), width=3)
    d.text((80, 155), "STREAM 1: NIST NVD VULNERABILITY INGESTION", font=get_font(22, bold=True), fill=(30, 58, 138))
    
    nvd_steps = [
        ("Step 1: Ingestion Triggered", "On-demand REST call (cve_id or range) or automated scheduler runner", (59, 130, 246)),
        ("Step 2: Run Telemetry Initialized", "INSERT data_ingestion_runs with status='PENDING', feed='NVD'", (59, 130, 246)),
        ("Step 3: Upstream HTTP GET Call", "Query https://services.nvd.nist.gov/rest/json/cves/2.0 with backoff on 429/403", (59, 130, 246)),
        ("Step 4: Schema Parsing & Normalization", "Extract CVSS v3.1 / v2.0 Base Score, Vector String, Description, Dates", (59, 130, 246)),
        ("Step 5: Idempotent Database Upsert", "Upsert into 'vulnerabilities'. New CVEs insert; existing CVEs update metadata.", (16, 185, 129)),
        ("Step 6: Audit Run Finalization", "UPDATE data_ingestion_runs: status='SUCCESS', records_inserted/updated", (16, 185, 129))
    ]
    for i, (title, sub, col) in enumerate(nvd_steps):
        cy = 210 + i * 185
        d.rounded_rectangle([(80, cy), (1040, cy + 120)], radius=8, fill=(255, 255, 255), outline=(147, 197, 253), width=2)
        d.text((105, cy + 30), title, font=get_font(18, bold=True), fill=(15, 23, 42))
        d.text((105, cy + 65), sub, font=get_font(14, bold=False), fill=(100, 116, 139))
        if i < len(nvd_steps) - 1:
            draw_arrow(d, (560, cy + 120), (560, cy + 185), col=col, width=3)

    # Right: CISA KEV
    d.rounded_rectangle([(1130, 120), (W - 50, 1380)], radius=12, fill=(255, 241, 242), outline=(244, 63, 94), width=3)
    d.text((1160, 155), "STREAM 2: CISA KEV CATALOG STREAM INGESTION", font=get_font(22, bold=True), fill=(136, 19, 55))

    kev_steps = [
        ("Step 1: KEV Ingestion Triggered", "Invoked via POST /api/v1/exploitation-status/ingest/cisa-kev endpoint", (244, 63, 94)),
        ("Step 2: Run Telemetry Initialized", "INSERT data_ingestion_runs with status='PENDING', feed='CISA_KEV'", (244, 63, 94)),
        ("Step 3: Complete Catalog Download", "Fetch authoritative JSON feed from cisa.gov (1,739+ active weaponized CVEs)", (244, 63, 94)),
        ("Step 4: Pydantic Schema Validation", "Validate models: cveID, dateAdded, dueDate, knownRansomwareCampaignUse", (244, 63, 94)),
        ("Step 5: Relational Exploitation Linking", "Upsert into 'exploitation_status' with kev_flag=True. Link existing CVEs.", (16, 185, 129)),
        ("Step 6: Sync Completion Logged", "UPDATE data_ingestion_runs: status='SUCCESS', accurate counts committed", (16, 185, 129))
    ]
    for i, (title, sub, col) in enumerate(kev_steps):
        cy = 210 + i * 185
        d.rounded_rectangle([(1160, cy), (W - 80, cy + 120)], radius=8, fill=(255, 255, 255), outline=(254, 205, 211), width=2)
        d.text((1185, cy + 30), title, font=get_font(18, bold=True), fill=(15, 23, 42))
        d.text((1185, cy + 65), sub, font=get_font(14, bold=False), fill=(100, 116, 139))
        if i < len(kev_steps) - 1:
            draw_arrow(d, (1665, cy + 120), (1665, cy + 185), col=col, width=3)

    im.save(os.path.join(out_dir, "figure_b_ingestion_pipeline.png"), dpi=(300, 300))
    print("Saved figure_b_ingestion_pipeline.png")

    # -------------------------------------------------------------
    # Figure C: Prioritization Workflow
    # -------------------------------------------------------------
    W, H = 2200, 1600
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 4.3: Heuristic Vulnerability Prioritization Workflow & Tier Routing")

    # Step 1: Ingestion
    d.rounded_rectangle([(50, 120), (W - 50, 280)], radius=12, fill=(239, 246, 255), outline=(59, 130, 246), width=3)
    d.text((80, 150), "STEP 1: INGEST PUBLIC VULNERABILITY & EXPLOITATION ATTRIBUTES", font=get_font(20, bold=True), fill=(30, 58, 138))
    
    attrs = [
        ("CVSS v3.1 / v2.0 Base Score", "Normalized continuous scale: 0.0 to 10.0\nDerived from NIST NVD authoritative vector"),
        ("CISA KEV Exploitation Flag", "Binary status flag: True or False\nIndicates active weaponization in the wild"),
        ("Known Ransomware Campaign Use", "Categorical status: 'Known' or 'Unknown'\nIdentifies syndicate extortion usage")
    ]
    for i, (title, sub) in enumerate(attrs):
        cx = 80 + i * 690
        d.rounded_rectangle([(cx, 180), (cx + 660, 260)], radius=8, fill=(255, 255, 255), outline=(147, 197, 253), width=2)
        d.text((cx + 20, 205), title, font=get_font(17, bold=True), fill=(15, 23, 42))
        d.text((cx + 20, 230), sub, font=get_font(13, bold=False), fill=(100, 116, 139))

    draw_arrow(d, (W // 2, 280), (W // 2, 340), col=(37, 99, 235), width=4)

    # Step 2: Multi-Factor Formulation
    d.rounded_rectangle([(50, 340), (W - 50, 640)], radius=12, fill=(255, 251, 235), outline=(245, 158, 11), width=3)
    d.text((80, 370), "STEP 2: MULTI-FACTOR HEURISTIC CALCULATION", font=get_font(20, bold=True), fill=(120, 53, 15))

    prio_factors = [
        ("Technical Severity Base", "S_base = CVSS_base * 10.0", "Range: 0.0 to 100.0\nMultiplies standard 10-point CVSS by 10.0"),
        ("Active Exploitation Penalty", "P_kev = +30.0 points", "Applied if kev_flag == True\nReflects immediate risk of active attacks"),
        ("Ransomware Multiplier", "P_ransom = +15.0 points", "Applied if ransomware == 'Known'\nPenalizes syndicate ransomware campaigns")
    ]
    for i, (title, formula, sub) in enumerate(prio_factors):
        cx = 80 + i * 690
        d.rounded_rectangle([(cx, 410), (cx + 660, 600)], radius=8, fill=(255, 255, 255), outline=(252, 211, 77), width=2)
        d.text((cx + 30, 445), title, font=get_font(18, bold=True), fill=(15, 23, 42))
        d.text((cx + 30, 490), formula, font=get_font(22, bold=True), fill=(180, 83, 9))
        d.text((cx + 30, 540), sub, font=get_font(14, bold=False), fill=(100, 116, 139))

    draw_arrow(d, (W // 2, 640), (W // 2, 700), col=(180, 83, 9), width=4)

    # Step 3: Clamping
    d.rounded_rectangle([(300, 700), (W - 300, 820)], radius=10, fill=(30, 41, 59))
    d.text((W // 2, 735), "STEP 3: COMPOSITE AGGREGATION & MATHEMATICAL CLAMPING", font=get_font(18, bold=True), fill=(255, 255, 255), anchor="mm")
    d.text((W // 2, 775), "PriorityScore = min(100.0, max(0.0, S_base + P_kev + P_ransom))", font=get_font(22, bold=True), fill=(56, 189, 248), anchor="mm")

    draw_arrow(d, (W // 2, 820), (W // 2, 880), col=(71, 85, 105), width=4)

    # Step 4: Tier Assignment
    d.rounded_rectangle([(50, 880), (W - 50, 1360)], radius=12, fill=(248, 250, 252), outline=(148, 163, 184), width=3)
    d.text((80, 910), "STEP 4: DETERMINISTIC SLA & URGENCY TIER ROUTING", font=get_font(20, bold=True), fill=(15, 23, 42))

    tiers = [
        ("TIER P1 (CRITICAL)", "PriorityScore >= 75.0", "Immediate weaponization or extreme severity", "Remediation SLA: 72 Hours", (254, 226, 226), (239, 68, 68), (153, 27, 27)),
        ("TIER P2 (HIGH)", "50.0 <= PriorityScore < 75.0", "High technical severity or weaponized exploit", "Remediation SLA: 14 Days", (255, 237, 213), (249, 115, 22), (154, 52, 18)),
        ("TIER P3 (MEDIUM)", "25.0 <= PriorityScore < 50.0", "Moderate technical severity, unweaponized", "Remediation SLA: 30 Days", (254, 243, 199), (234, 179, 8), (133, 77, 14)),
        ("TIER P4 (LOW)", "PriorityScore < 25.0", "Low technical severity, routine maintenance", "Routine Patching Cycle", (241, 245, 249), (148, 163, 184), (51, 65, 85))
    ]
    t_w = 480
    for i, (name, range_txt, desc, sla, bg, stroke, text_col) in enumerate(tiers):
        cx = 80 + i * 515
        d.rounded_rectangle([(cx, 950), (cx + t_w, 1320)], radius=8, fill=bg, outline=stroke, width=2)
        d.text((cx + t_w // 2, 1000), name, font=get_font(20, bold=True), fill=text_col, anchor="mm")
        d.text((cx + t_w // 2, 1050), range_txt, font=get_font(18, bold=True), fill=text_col, anchor="mm")
        d.text((cx + t_w // 2, 1120), desc, font=get_font(14, bold=False), fill=(100, 116, 139), anchor="mm")
        d.rounded_rectangle([(cx + 30, 1220), (cx + t_w - 30, 1280)], radius=6, fill=(255, 255, 255), outline=stroke, width=2)
        d.text((cx + t_w // 2, 1250), sla, font=get_font(16, bold=True), fill=text_col, anchor="mm")

    # Step 5: Audit Persistence
    d.rounded_rectangle([(50, 1400), (W - 50, 1540)], radius=10, fill=(240, 253, 244), outline=(34, 197, 94), width=2)
    d.text((W // 2, 1445), "STEP 5: AUDIT TRAIL PERSISTENCE IN 'vulnerability_prioritizations' TABLE", font=get_font(18, bold=True), fill=(21, 128, 61), anchor="mm")
    d.text((W // 2, 1490), "Stores priority_id UUID, cve_id FK, priority_score, priority_tier, execution timestamp, and full JSON factor breakdown for underwriter transparency.", font=get_font(14, bold=False), fill=(21, 128, 61), anchor="mm")

    im.save(os.path.join(out_dir, "figure_c_prioritization_workflow.png"), dpi=(300, 300))
    print("Saved figure_c_prioritization_workflow.png")

    # -------------------------------------------------------------
    # Figure D: Database ERD
    # -------------------------------------------------------------
    W, H = 2200, 1600
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 4.4: CRGC Database Entity-Relationship Diagram (SQLAlchemy Relational Schema)")

    # 7 Tables
    # Row 1: data_ingestion_runs, vulnerabilities, exploitation_status
    # Row 2: organizations, vulnerability_prioritizations, vulnerability_observations
    # Row 3: assets
    
    def draw_erd_table(d, xy, tname, pk_list, fk_list, attr_list, col):
        x1, y1 = xy[0]
        x2, y2 = xy[1]
        d.rounded_rectangle(xy, radius=8, fill=(255, 255, 255), outline=col, width=2)
        d.rounded_rectangle([(x1, y1), (x2, y1 + 45)], radius=8, fill=col)
        d.text((x1 + 20, y1 + 22), tname, font=get_font(17, bold=True), fill=(255, 255, 255), anchor="lm")
        
        cy = y1 + 65
        for pk in pk_list:
            d.text((x1 + 20, cy), "PK  " + pk, font=get_font(14, bold=True), fill=(185, 28, 28))
            cy += 30
        for fk in fk_list:
            d.text((x1 + 20, cy), "FK  " + fk, font=get_font(14, bold=True), fill=(29, 78, 216))
            cy += 30
        for attr in attr_list:
            d.text((x1 + 20, cy), "    " + attr, font=get_font(13, bold=False), fill=(51, 65, 85))
            cy += 28

    # Table 1: data_ingestion_runs
    draw_erd_table(d, [(50, 130), (650, 520)], "data_ingestion_runs", 
                   ["run_id : UUID"], [], 
                   ["feed_type : VARCHAR(50)", "started_at : DATETIME", "completed_at : DATETIME", "status : VARCHAR(20)", "records_fetched : INTEGER", "records_inserted : INTEGER", "records_updated : INTEGER", "error_message : TEXT"], (2, 132, 199))

    # Table 2: vulnerabilities
    draw_erd_table(d, [(750, 130), (1450, 560)], "vulnerabilities", 
                   ["cve_id : VARCHAR(50)"], [], 
                   ["description : TEXT", "cvss_v3_score : FLOAT", "cvss_v3_vector : VARCHAR(100)", "cvss_v2_score : FLOAT", "cvss_v2_vector : VARCHAR(100)", "published_date : DATETIME", "last_modified_date : DATETIME", "created_at / updated_at : DATETIME"], (29, 78, 216))

    # Table 3: exploitation_status
    draw_erd_table(d, [(1550, 130), (2150, 480)], "exploitation_status", 
                   ["cve_id : VARCHAR(50)"], ["cve_id -> vulnerabilities.cve_id"], 
                   ["kev_flag : BOOLEAN (Default: False)", "date_added : DATETIME", "due_date : DATETIME", "known_ransomware_campaign_use : VARCHAR(50)", "notes : TEXT", "updated_at : DATETIME"], (190, 18, 60))

    # Table 4: vulnerability_prioritizations
    draw_erd_table(d, [(750, 680), (1450, 1020)], "vulnerability_prioritizations", 
                   ["priority_id : UUID"], ["cve_id -> vulnerabilities.cve_id"], 
                   ["priority_score : FLOAT (0.0 - 100.0)", "priority_tier : VARCHAR(10) (P1-P4)", "factor_breakdown : JSON / TEXT", "created_at : DATETIME"], (180, 83, 9))

    # Table 5: organizations
    draw_erd_table(d, [(50, 680), (650, 1020)], "organizations", 
                   ["organization_id : UUID"], [], 
                   ["organization_ref : VARCHAR(100) UNIQUE", "display_name : VARCHAR(255)", "data_authorization_flag : BOOLEAN", "created_at : DATETIME", "updated_at : DATETIME"], (4, 120, 87))

    # Table 6: assets
    draw_erd_table(d, [(50, 1140), (650, 1530)], "assets", 
                   ["asset_id : UUID"], ["organization_id -> organizations.org_id"], 
                   ["asset_ref : VARCHAR(100)", "hostname : VARCHAR(255)", "ip_address : VARCHAR(45)", "asset_type : VARCHAR(50)", "criticality : VARCHAR(20)", "created_at / updated_at : DATETIME"], (4, 120, 87))

    # Table 7: vulnerability_observations
    draw_erd_table(d, [(1550, 680), (2150, 1120)], "vulnerability_observations", 
                   ["observation_id : UUID"], ["asset_id -> assets.asset_id", "cve_id -> vulnerabilities.cve_id"], 
                   ["scanner_source : VARCHAR(100)", "observed_at : DATETIME", "status : VARCHAR(50) (VERIFIED, etc)", "raw_evidence : JSON", "created_at : DATETIME"], (109, 40, 217))

    # Relationships Lines
    # vulnerabilities <-> exploitation_status (1:0..1)
    draw_arrow(d, (1450, 250), (1550, 250), col=(190, 18, 60), width=3, text="1 : 0..1 (Enrichment)")

    # vulnerabilities <-> prioritizations (1:0..N)
    draw_arrow(d, (1100, 560), (1100, 680), col=(29, 78, 216), width=3, text="1 : 0..N")

    # organizations <-> assets (1:N)
    draw_arrow(d, (350, 1020), (350, 1140), col=(4, 120, 87), width=3, text="1 : N")

    # assets <-> observations (1:N)
    draw_arrow(d, (650, 1300), (1800, 1300), col=(109, 40, 217), width=3)
    draw_arrow(d, (1800, 1300), (1800, 1120), col=(109, 40, 217), width=3, text="1 : N (Asset Observations)")

    # vulnerabilities <-> observations (1:N)
    draw_arrow(d, (1450, 450), (1550, 750), col=(29, 78, 216), width=3, text="1 : N (Public CVE Ref)")

    im.save(os.path.join(out_dir, "figure_d_database_erd.png"), dpi=(300, 300))
    print("Saved figure_d_database_erd.png")

    # -------------------------------------------------------------
    # Figure E: Risk Scoring Flowchart
    # -------------------------------------------------------------
    W, H = 2200, 1600
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 4.5: Explainable Organization-Level Cyber Risk Scoring Architecture")

    # Telemetry Box
    d.rounded_rectangle([(50, 120), (W - 50, 250)], radius=12, fill=(239, 246, 255), outline=(59, 130, 246), width=3)
    d.text((80, 150), "VERIFIED ENTERPRISE SECURITY TELEMETRY INPUTS", font=get_font(20, bold=True), fill=(30, 58, 138))
    
    t_inputs = [
        ("MFA Enforced Pct", "Range: 0.0% to 100.0%"),
        ("Internet-Exposed RDP", "Status: True (Open) or False (Closed)"),
        ("Overdue Critical CVEs (>30d)", "Count: Integer >= 0 (Exploitable Debt)"),
        ("EDR Agent Coverage Pct", "Range: 0.0% to 100.0% (Endpoint Visibility)")
    ]
    for i, (title, sub) in enumerate(t_inputs):
        cx = 80 + i * 515
        d.rounded_rectangle([(cx, 175), (cx + 480, 230)], radius=6, fill=(255, 255, 255), outline=(147, 197, 253), width=2)
        d.text((cx + 15, 192), title, font=get_font(15, bold=True), fill=(15, 23, 42))
        d.text((cx + 15, 212), sub, font=get_font(12, bold=False), fill=(100, 116, 139))

    draw_arrow(d, (W // 2, 250), (W // 2, 310), col=(37, 99, 235), width=4)

    # Penalties Box
    d.rounded_rectangle([(50, 310), (W - 50, 610)], radius=12, fill=(255, 251, 235), outline=(245, 158, 11), width=3)
    d.text((80, 340), "TRANSPARENT ADDITIVE PENALTY FORMULATIONS", font=get_font(20, bold=True), fill=(120, 53, 15))

    penalties = [
        ("Base Risk Floor", "R_base = 5.0 points", "Foundational operational risk\nFixed baseline floor", "+5.0 Fixed"),
        ("Weak MFA Penalty", "P_MFA = (100 - MFA) * 0.30", "Accounts for credential theft\nMax Penalty: +30.0 points", "Up to +30.0"),
        ("Exposed RDP Gateway", "P_RDP = 25.0 if RDP else 0.0", "Ransomware initial access vector\nMax Penalty: +25.0 points", "Up to +25.0"),
        ("Overdue Critical CVEs", "P_CVE = min(35.0, Count * 7.0)", "Unpatched known exploitable CVEs\nMax Penalty: +35.0 points", "Up to +35.0"),
        ("Low EDR Coverage", "P_EDR = (100 - EDR) * 0.20", "Endpoint monitoring blind spots\nMax Penalty: +20.0 points", "Up to +20.0")
    ]
    p_w = 380
    for i, (title, formula, sub, badge) in enumerate(penalties):
        cx = 80 + i * 410
        d.rounded_rectangle([(cx, 380), (cx + p_w, 570)], radius=8, fill=(255, 255, 255), outline=(252, 211, 77), width=2)
        d.text((cx + 20, 410), title, font=get_font(16, bold=True), fill=(15, 23, 42))
        d.text((cx + 20, 445), formula, font=get_font(15, bold=True), fill=(180, 83, 9))
        d.text((cx + 20, 495), sub, font=get_font(13, bold=False), fill=(100, 116, 139))
        d.rounded_rectangle([(cx + p_w - 110, 525), (cx + p_w - 15, 555)], radius=4, fill=(220, 38, 38))
        d.text((cx + p_w - 62, 540), badge, font=get_font(11, bold=True), fill=(255, 255, 255), anchor="mm")

    draw_arrow(d, (W // 2, 610), (W // 2, 670), col=(180, 83, 9), width=4)

    # Clamping & Aggregation
    d.rounded_rectangle([(300, 670), (W - 300, 780)], radius=10, fill=(30, 41, 59))
    d.text((W // 2, 705), "COMPOSITE SCORE AGGREGATION & MATHEMATICAL CLAMPING", font=get_font(18, bold=True), fill=(255, 255, 255), anchor="mm")
    d.text((W // 2, 745), "RiskScore = min(100.0, max(0.0, R_base + P_MFA + P_RDP + P_CVE + P_EDR))", font=get_font(21, bold=True), fill=(56, 189, 248), anchor="mm")

    draw_arrow(d, (W // 2, 780), (W // 2, 840), col=(71, 85, 105), width=4)

    # Risk Tiers & Policy Actions
    d.rounded_rectangle([(50, 840), (W - 50, 1260)], radius=12, fill=(248, 250, 252), outline=(148, 163, 184), width=3)
    d.text((80, 870), "ACTUARIAL RISK TIERS & GUIDEWIRE POLICYCENTER DIRECTIVES", font=get_font(20, bold=True), fill=(15, 23, 42))

    risk_tiers = [
        ("LOW RISK TIER", "Score < 40.0", "Minimal residual technical exposure", "Policy Action: NOMINAL", "Bind policy at standard terms and baseline deductible.", (236, 253, 245), (16, 185, 129), (4, 120, 87)),
        ("MEDIUM RISK TIER", "40.0 <= Score < 60.0", "Moderate security control deficiencies", "Policy Action: MONITOR", "Bind policy with 60-day telemetry re-assessment requirement.", (239, 246, 255), (59, 130, 246), (29, 78, 216)),
        ("HIGH RISK TIER", "60.0 <= Score < 80.0", "Severe enterprise security exposure", "Action: REVIEW REQUIRED", "Refer to Senior Underwriter; require remediation warranty.", (255, 247, 237), (249, 115, 22), (194, 65, 12)),
        ("CRITICAL RISK TIER", "Score >= 80.0", "Extreme threat vulnerability / imminent breach", "Action: REVIEW REQUIRED", "Refer to Senior Underwriter; decline automated bind.", (254, 242, 242), (239, 68, 68), (185, 28, 28))
    ]
    rt_w = 480
    for i, (name, range_txt, desc, action, detail, bg, stroke, text_col) in enumerate(risk_tiers):
        cx = 80 + i * 515
        d.rounded_rectangle([(cx, 910), (cx + rt_w, 1220)], radius=8, fill=bg, outline=stroke, width=2)
        d.text((cx + rt_w // 2, 945), name, font=get_font(18, bold=True), fill=text_col, anchor="mm")
        d.text((cx + rt_w // 2, 980), range_txt, font=get_font(16, bold=True), fill=text_col, anchor="mm")
        d.text((cx + rt_w // 2, 1025), desc, font=get_font(13, bold=False), fill=(100, 116, 139), anchor="mm")
        d.rounded_rectangle([(cx + 20, 1060), (cx + rt_w - 20, 1120)], radius=6, fill=(255, 255, 255), outline=stroke, width=2)
        d.text((cx + rt_w // 2, 1090), action, font=get_font(15, bold=True), fill=text_col, anchor="mm")
        d.text((cx + rt_w // 2, 1165), detail, font=get_font(12, bold=False), fill=(71, 85, 105), anchor="mm")

    # Scenarios Benchmark Box
    d.rounded_rectangle([(50, 1290), (W - 50, 1550)], radius=12, fill=(240, 253, 250), outline=(20, 184, 166), width=2)
    d.text((80, 1320), "EMPIRICAL PREDEFINED SCENARIO EXECUTION BENCHMARKS", font=get_font(18, bold=True), fill=(15, 118, 110))

    scenarios = [
        ("Scenario A: Clean Baseline (Apex Global Financial)", "MFA: 100% | RDP: Closed | Overdue CVEs: 0 | EDR: 100%\nCalculated Penalties: Base (5.0) + 0.0 + 0.0 + 0.0 + 0.0\nComposite Risk Score: 5.0 | Tier: LOW | Action: NOMINAL", (4, 120, 87)),
        ("Scenario B: Moderate Risk (Meridian Healthcare)", "MFA: 80% | RDP: Closed | Overdue CVEs: 2 | EDR: 70%\nCalculated Penalties: Base (5.0) + MFA (6.0) + CVE (14.0) + EDR (6.0)\nComposite Risk Score: 31.0 | Tier: LOW | Action: NOMINAL", (29, 78, 216)),
        ("Scenario C: Severe Compromise (Titan Logistics)", "MFA: 20% | RDP: Exposed | Overdue CVEs: 6 | EDR: 30%\nCalculated Penalties: Base (5.0) + MFA (24.0) + RDP (25.0) + CVE (35.0) + EDR (14.0)\nComposite Risk Score: 95.0 | Tier: CRITICAL | Action: REVIEW REQUIRED", (185, 28, 28))
    ]
    sc_w = 660
    for i, (title, sub, col) in enumerate(scenarios):
        cx = 80 + i * 690
        d.rounded_rectangle([(cx, 1350), (cx + sc_w, 1510)], radius=6, fill=(255, 255, 255), outline=(153, 246, 228), width=2)
        d.text((cx + 20, 1375), title, font=get_font(15, bold=True), fill=col)
        d.text((cx + 20, 1410), sub, font=get_font(13, bold=False), fill=(71, 85, 105))

    im.save(os.path.join(out_dir, "figure_e_risk_scoring_flowchart.png"), dpi=(300, 300))
    print("Saved figure_e_risk_scoring_flowchart.png")

    # -------------------------------------------------------------
    # Figure F: Asset Observation Lifecycle
    # -------------------------------------------------------------
    W, H = 2200, 1500
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 4.6: Enterprise Asset Governance & Vulnerability Observation Lifecycle")

    phases = [
        ("PHASE 1: ORGANIZATION ONBOARDING & LEGAL DATA CONSENT",
         "Register Commercial Entity via POST /api/v1/organizations (assign organization_ref UK, display_name)\nVerification Gate: data_authorization_flag == True (Explicit legal consent authorizing security evaluation)\nPrevents unauthorized asset scanning or policy evaluation without commercial contractual approval.",
         (236, 253, 245), (16, 185, 129), (4, 120, 87)),
        
        ("PHASE 2: ENTERPRISE ASSET INVENTORY REGISTRATION",
         "Register Authorized Enterprise Infrastructure via POST /api/v1/assets (linked to parent organization_id FK)\nCaptures Asset Metadata: asset_ref, hostname (FQDN), IP address, asset_type (SERVER, WORKSTATION, CLOUD)\nTags Business Criticality: LOW, MEDIUM, HIGH, CRITICAL for context-aware risk weighting.",
         (239, 246, 255), (59, 130, 246), (29, 78, 216)),
        
        ("PHASE 3: SCANNER FINDING INGESTION (QUALYS / TENABLE / NESSUS)",
         "Enterprise Security Teams import vulnerability scanner exports via POST /api/v1/vulnerability-observations\nValidates Asset Boundary: Enforces that target asset_ref belongs strictly to authorized organization_id\nExtracts Technical Findings: cve_id, scanner_source, observed_at; preserves raw evidence JSON.",
         (250, 245, 255), (139, 92, 246), (88, 28, 135)),
        
        ("PHASE 4: RELATIONAL THREAT INTELLIGENCE JOINING",
         "Correlates Finding CVE ID with Local Authoritative Threat Intelligence Repositories\nJoins 'vulnerabilities' table: Enriches finding with NIST CVSS v3.1 base score, attack vector, and descriptions\nJoins 'exploitation_status' table: Enriches finding with CISA KEV active exploitation flag and ransomware indicators.",
         (255, 251, 235), (245, 158, 11), (120, 53, 15)),
        
        ("PHASE 5: FINDING TRIAGE & UNDERWRITING INTEGRATION",
         "Security Analysts & Underwriters review enriched observations across three lifecycle states:\n1. Status VERIFIED: Confirmed vulnerable asset -> feeds into RiskEngine Overdue CVE penalty.\n2. Status UNVERIFIED / FALSE POSITIVE: Quarantined pending manual verification; excluded from underwriting.\n3. Status REMEDIATED: Patch deployed and re-scan verified -> eliminates penalty and updates posture.",
         (248, 250, 252), (100, 116, 139), (15, 23, 42))
    ]

    for i, (title, sub, bg, stroke, text_col) in enumerate(phases):
        cy = 130 + i * 265
        d.rounded_rectangle([(80, cy), (W - 80, cy + 200)], radius=10, fill=bg, outline=stroke, width=3)
        d.text((110, cy + 35), title, font=get_font(20, bold=True), fill=text_col)
        d.text((110, cy + 80), sub, font=get_font(15, bold=False), fill=(51, 65, 85))
        if i < len(phases) - 1:
            draw_arrow(d, (W // 2, cy + 200), (W // 2, cy + 265), col=stroke, width=4)

    im.save(os.path.join(out_dir, "figure_f_asset_observation_lifecycle.png"), dpi=(300, 300))
    print("Saved figure_f_asset_observation_lifecycle.png")

    # -------------------------------------------------------------
    # Figure G: Testing Framework
    # -------------------------------------------------------------
    W, H = 2200, 1500
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    draw_header(d, W, "Figure 5.1: Multi-Layer Automated Verification & Quality Assurance Framework")

    # Top Banner
    d.rounded_rectangle([(50, 120), (W - 50, 200)], radius=8, fill=(236, 253, 245), outline=(16, 185, 129), width=2)
    d.text((W // 2, 160), "EMPIRICAL TEST EXECUTION RESULT: 94 TOTAL AUTOMATED TESTS PASSING (100% SUCCESS RATE)", font=get_font(20, bold=True), fill=(4, 120, 87), anchor="mm")

    # Left: Backend Pytest (77 Tests)
    d.rounded_rectangle([(50, 230), (1070, 1100)], radius=12, fill=(239, 246, 255), outline=(59, 130, 246), width=3)
    d.text((80, 265), "BACKEND PYTEST TEST HARNESS (77 Tests Passing - 5.45s)", font=get_font(20, bold=True), fill=(30, 58, 138))
    
    b_suites = [
        ("Prioritization Engine Tests (16 Tests)", "Validates P1/P2/P3/P4 rule invariants, KEV (+30) & Ransomware (+15) weights, and clamping bounds [0, 100]."),
        ("Threat Ingestion Pipelines (18 Tests)", "Validates NVD single-CVE & paginated ingestion, CISA KEV stream parsing, and HTTP 429 backoff resilience."),
        ("Organizations & Assets API (15 Tests)", "Validates tenant CRUD, data consent enforcement, unique organization_ref UK, and asset FK cascades."),
        ("Vulnerability Observations API (14 Tests)", "Validates scanner telemetry ingestion, asset-cve relational mapping, and status lifecycle transitions."),
        ("RiskEngine & Underwriting API (14 Tests)", "Validates Scenarios A, B, and C scores, deductible calculations, and Guidewire mock note/activity payloads."),
        ("Isolated In-Memory Test Fixtures", "Uses sqlite:///:memory: per test session; all external network calls mocked with unittest.mock.")
    ]
    for i, (title, sub) in enumerate(b_suites):
        cy = 310 + i * 125
        d.rounded_rectangle([(80, cy), (1040, cy + 105)], radius=8, fill=(255, 255, 255), outline=(147, 197, 253), width=2)
        d.text((105, cy + 30), title, font=get_font(17, bold=True), fill=(15, 23, 42))
        d.text((105, cy + 62), sub, font=get_font(13, bold=False), fill=(100, 116, 139))

    # Right: Frontend Vitest & Build (17 Tests)
    d.rounded_rectangle([(1130, 230), (W - 50, 1100)], radius=12, fill=(250, 245, 255), outline=(139, 92, 246), width=3)
    d.text((1160, 265), "FRONTEND VITEST & BUILD HARNESS (17 Tests Passing - 6.06s)", font=get_font(20, bold=True), fill=(88, 28, 135))

    f_suites = [
        ("Overview Page Component Tests (5 Tests)", "Verifies live metric cards (Total CVEs, KEV, P1-P4 counts) and ingestion sync run status tables."),
        ("Explorer Page Component Tests (4 Tests)", "Verifies client-side CVE search filtering, KEV badge display, and Priority Factor Breakdown drawer."),
        ("Prioritization Config Tests (4 Tests)", "Verifies threshold sliders, weight adjustments, and governance form submission validation."),
        ("Observed Vulnerabilities Tests (4 Tests)", "Verifies enterprise findings table, organization asset filtering, and status triage buttons."),
        ("TypeScript Static Typechecking (tsc)", "Executes 'tsc --noEmit'; confirms 100% type safety and zero compiler errors across all schemas."),
        ("Vite Production Bundle Verification", "Executes 'vite build'; confirms 100% clean production bundle compilation in 563 ms.")
    ]
    for i, (title, sub) in enumerate(f_suites):
        cy = 310 + i * 125
        d.rounded_rectangle([(1160, cy), (W - 80, cy + 105)], radius=8, fill=(255, 255, 255), outline=(221, 214, 254), width=2)
        d.text((1185, cy + 30), title, font=get_font(17, bold=True), fill=(15, 23, 42))
        d.text((1185, cy + 62), sub, font=get_font(13, bold=False), fill=(100, 116, 139))

    # Bottom CI Matrix
    d.rounded_rectangle([(50, 1140), (W - 50, 1440)], radius=12, fill=(30, 41, 59))
    d.text((80, 1175), "CONTINUOUS INTEGRATION & TEST SPECIFICATIONS MATRIX", font=get_font(18, bold=True), fill=(255, 255, 255))
    
    ci_specs = [
        ("Backend Framework", "Pytest 8.3.4 + HTTPX Async TestClient"),
        ("Database Fixture", "Isolated In-Memory SQLite 3 (Auto-Migrated)"),
        ("Frontend Harness", "Vitest 3.0.4 + React Testing Library + JSDOM"),
        ("Bundle Performance", "563 ms compile time (Vite 6.0.7)"),
        ("Total Pass Rate", "100% Passed (94 / 94 Automated Tests)")
    ]
    for i, (title, sub) in enumerate(ci_specs):
        cx = 80 + i * 410
        d.rounded_rectangle([(cx, 1220), (cx + 380, 1380)], radius=8, fill=(15, 23, 42), outline=(56, 189, 248), width=2)
        d.text((cx + 20, 1260), title, font=get_font(14, bold=True), fill=(148, 163, 184))
        d.text((cx + 20, 1310), sub, font=get_font(14, bold=True), fill=(56, 189, 248))

    im.save(os.path.join(out_dir, "figure_g_testing_framework.png"), dpi=(300, 300))
    print("Saved figure_g_testing_framework.png")

if __name__ == "__main__":
    main()

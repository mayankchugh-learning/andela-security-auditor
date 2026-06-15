# STAGE PROMPTS — andela-security-auditor
## Copy and paste each prompt in order into Claude Code or Cursor
## Do NOT skip stages. Complete each fully before moving to the next.

---

## STAGE 0 — KICKOFF PROMPT (paste this FIRST, verbatim)

```
Lead Architect mode: ON. We are building a Python-based, API-first
Enterprise Security Guardrail Auditor using a free database and a dashboard.

Rules:
- No Manual Edits: You provide all logic and fixes. I will not edit any code.
- Audit Log: You must maintain a file named prompts.md. After every turn,
  update that file with the prompt I just used.
- Time-Check: Start a timer. Goal is an MVP in 4-6 hours (Max window: 16h).
  Report Elapsed Time at the end of every response. Acknowledge and let's start.
```

---

## STAGE 1 — PROJECT SCAFFOLD

```
Create the full project structure for andela-security-auditor.
Create these directories and empty __init__.py files:
- app/scanner/
- app/rules/
- app/scoring/
- app/database/
- app/api/
- dashboard/
- sample_configs/
- tests/

Create these files with placeholder content:
- app/main.py (FastAPI app instance, include router, add /health endpoint)
- requirements.txt (fastapi, uvicorn, python-hcl2, pyyaml, sqlalchemy, pydantic, streamlit, python-multipart, requests)
- requirements-dev.txt (pytest, pytest-asyncio, httpx, ruff, black)
- .gitignore (Python standard)
- README.md (title and placeholder sections only)
- prompts.md (audit log header)

Update prompts.md with this turn. Report elapsed time.
```

---

## STAGE 2 — SAMPLE CONFIG FILES

```
Create 3 sample infrastructure config files in sample_configs/:

1. clean_infra.tf — Terraform file with NO violations:
   - S3 bucket with private ACL and encryption enabled
   - Security group with only port 443 open
   - IAM user with MFA enforced
   - EBS volume with encryption enabled

2. vulnerable_infra.tf — Terraform file with MULTIPLE violations:
   - S3 bucket with acl = "public-read" (PUBLIC_S3_BUCKET — Critical)
   - Security group with port 22 open to 0.0.0.0/0 (OPEN_SSH — High)
   - Security group with port 3389 open to 0.0.0.0/0 (OPEN_RDP — High)
   - IAM user with no MFA configuration (NO_MFA — Medium)
   - EBS volume with encrypted = false (UNENCRYPTED_EBS — High)

3. mixed_infra.yaml — CloudFormation template with:
   - 1 S3 bucket public violation (Critical)
   - 1 open SSH port violation (High)
   - 1 clean EC2 security group (no violation)
   - 1 clean encrypted RDS instance (no violation)

Make all files syntactically valid and realistic.
Update prompts.md. Report elapsed time.
```

---

## STAGE 3 — SCANNER + RULES ENGINE

```
Build the scanner and rules engine:

1. app/scanner/hcl_parser.py:
   - Function: parse_terraform(file_path: str) -> dict
   - Uses python-hcl2 to parse .tf files
   - Returns dict of all resource blocks
   - Handles parse errors gracefully with logging

2. app/scanner/cf_parser.py:
   - Function: parse_cloudformation(file_path: str) -> dict
   - Uses pyyaml to parse .yaml/.yml files
   - Returns dict of all Resources
   - Handles parse errors gracefully with logging

3. app/rules/definitions.py:
   - Define a Rule dataclass: rule_id, severity, points, description
   - Define all 8 rules:
     PUBLIC_S3_BUCKET (Critical, 40pts)
     OPEN_SSH (High, 25pts)
     OPEN_RDP (High, 25pts)
     OPEN_ALL_PORTS (Critical, 40pts)
     NO_MFA (Medium, 20pts)
     WEAK_IAM_POLICY (Medium, 20pts)
     UNENCRYPTED_EBS (High, 25pts)
     HTTP_LISTENER (Medium, 20pts)

4. app/rules/engine.py:
   - Function: run_rules(resources: dict, file_type: str) -> list[Finding]
   - Finding dataclass: rule_id, severity, points, resource_name, description
   - Apply each rule to each resource block
   - Return list of all findings

Test the scanner and rules engine against all 3 sample files.
Update prompts.md. Report elapsed time.
```

---

## STAGE 4 — RISK SCORING + DATABASE

```
Build the risk scoring algorithm and SQLite database:

1. app/scoring/risk_score.py:
   - Function: calculate_risk_score(findings: list[Finding]) -> int
   - Critical=40pts, High=25pts, Medium=20pts, Low=15pts
   - Score = min(sum of all finding points, 100)
   - Returns integer 0-100

2. app/database/models.py — SQLAlchemy models:
   - ScanResult: id (PK), filename, scan_timestamp, risk_score,
     total_findings, critical_count, high_count, medium_count, low_count, status
   - Finding: id (PK), scan_id (FK -> ScanResult.id), rule_id, severity,
     points, resource_name, description

3. app/database/session.py:
   - SQLite database URL: sqlite:///./security_auditor.db
   - Engine creation
   - SessionLocal factory
   - get_db() dependency for FastAPI
   - create_tables() function — call on app startup

Test risk scoring with findings from Stage 3 sample files.
Verify correct scores: vulnerable_infra.tf should score 100 (capped).
Update prompts.md. Report elapsed time.
```

---

## STAGE 5 — FASTAPI LAYER

```
Build the complete FastAPI application:

1. app/api/routes.py — all endpoints:

   POST /scan
   - Accepts multipart file upload (.tf or .yaml)
   - Saves file temporarily
   - Detects file type by extension
   - Runs appropriate parser
   - Runs rules engine
   - Calculates risk score
   - Saves ScanResult and all Findings to SQLite
   - Returns: ScanResponse (scan_id, filename, risk_score, risk_level,
     total_findings, findings list)
   - Cleans up temp file

   GET /scans
   - Returns list of all ScanResult records
   - Ordered by scan_timestamp descending
   - Returns: list of ScanSummary

   GET /scans/{scan_id}
   - Returns full ScanResult with all associated Findings
   - Returns 404 if not found

   GET /health
   - Returns: {"status": "ok", "service": "security-auditor", "version": "1.0.0"}

2. app/main.py — wire everything together:
   - Include router
   - Add startup event to create DB tables
   - Add CORS middleware (allow all origins for demo)
   - OpenAPI title: "Enterprise Security Guardrail Auditor"

3. Add Pydantic response models for all endpoints in app/api/schemas.py

Test all endpoints using the FastAPI /docs interface with sample config files.
Fix any issues found.
Update prompts.md. Report elapsed time.
```

---

## STAGE 6 — STREAMLIT DASHBOARD

```
Build the complete Streamlit dashboard in dashboard/app.py:

Layout:
1. Header: "🔒 Enterprise Security Guardrail Auditor" with subtitle
   "Scan Terraform & CloudFormation files for security misconfigurations"

2. Sidebar:
   - File uploader accepting .tf and .yaml files
   - "Scan Now" button
   - API URL setting (default: http://localhost:8000)

3. Main area — after scan:
   - Large Risk Score display with colour:
     0-25: Green background — "LOW RISK"
     26-50: Yellow background — "MEDIUM RISK"
     51-75: Orange background — "HIGH RISK"
     76-100: Red background — "CRITICAL RISK"
   - 4 metric columns: Total Findings / Critical / High / Medium
   - Findings table with columns: Severity (colour-coded badge),
     Rule ID, Resource Name, Description, Points
   - Sort findings by severity (Critical first)

4. Scan History section (always visible):
   - Table of all past scans from GET /scans
   - Columns: Filename, Risk Score, Risk Level, Total Findings, Timestamp
   - Click scan_id to load full findings (optional — use st.expander)

5. Empty state: show instructions when no scan has been run yet

Make it clean, professional, and visually impressive for a screenshot.
Update prompts.md. Report elapsed time.
```

---

## STAGE 7 — README + PRESENTATION DECK

```
Generate two complete documents:

1. README.md — full content:
   - Title and badges (Python, FastAPI, Streamlit, SQLite)
   - One-line description
   - ASCII architecture diagram showing:
     [.tf/.yaml files] -> [Scanner] -> [Rules Engine] -> [Risk Scorer]
     -> [SQLite DB] -> [FastAPI] -> [Streamlit Dashboard]
   - Security rules table (all 8 rules with severity and points)
   - Risk score legend (0-25 Low, 26-50 Medium, 51-75 High, 76-100 Critical)
   - Quick start: pip install + uvicorn command + streamlit command
   - API reference table
   - Sample output description
   - Tech stack table
   - About the architect section:
     "Built by Mayank Chugh — Senior Enterprise Architect with 20+ years
     delivering technology at Cathay Pacific, HSBC, British Airways, CHANEL,
     and M&S. HashiCorp Terraform Associate certified. Andela FDE candidate."

2. presentation.md — Marp-compatible Markdown slides:
   Slide 1: Title — Enterprise Security Guardrail Auditor | Mayank Chugh | Andela FDE
   Slide 2: The Problem — cloud misconfigs are the #1 cause of data breaches
   Slide 3: Solution Architecture (ASCII diagram)
   Slide 4: Security Rules & Risk Scoring Algorithm (table)
   Slide 5: Tech Stack (table)
   Slide 6: Key Features — scanner, API, dashboard, audit trail
   Slide 7: Vibe Coding Workflow — architect directs, AI executes, prompts.md audits
   Slide 8: About the Architect — Mayank Chugh background + Terraform cert

Update prompts.md. Report elapsed time.
```

---

## STAGE 8 — TESTS + FINAL POLISH

```
Final stage — tests, polish, and submission prep:

1. Write pytest tests in tests/:
   - test_scanner.py: test hcl_parser and cf_parser against sample files
   - test_rules.py: test rules engine — verify vulnerable_infra.tf produces
     correct findings (PUBLIC_S3_BUCKET, OPEN_SSH, OPEN_RDP, NO_MFA, UNENCRYPTED_EBS)
   - test_api.py: test all FastAPI endpoints using httpx TestClient

2. Run all tests — fix any failures

3. Run the full application end to end:
   - Start FastAPI: uvicorn app.main:app --reload
   - Start Streamlit: streamlit run dashboard/app.py
   - Scan all 3 sample files
   - Verify risk scores:
     clean_infra.tf → score 0
     vulnerable_infra.tf → score 100 (capped)
     mixed_infra.yaml → score between 40-65

4. Final prompts.md — verify all turns are logged correctly

5. Provide complete git commands:
   git init
   git add .
   git commit -m "feat: complete Enterprise Security Guardrail Auditor — Andela FDE challenge"
   git branch -M main
   git remote add origin https://github.com/mayankchugh-learning/andela-security-auditor.git
   git push -u origin main

Report TOTAL elapsed time for the complete project.
```

---

## SUBMISSION EMAIL TEMPLATE

Send to: florencia.vattino@andela.com
CC: guilherme.pompeo@andela.com

Subject: Andela FDE Technical Challenge Submission — Mayank Chugh

Body:
Hi Florencia and Guilherme,

Please find my technical challenge submission below.

Project: Enterprise Security Guardrail Auditor (Project 2)
GitHub: https://github.com/mayankchugh-learning/andela-security-auditor
Tagle.ai Tag: [INSERT YOUR TAG]

Deliverables included in the repository:
- Full source code (Python, FastAPI, Streamlit, SQLite)
- prompts.md — complete AI prompt audit log
- README.md — architecture and setup guide
- presentation.md — solution deck

No cloud resources were provisioned. The application runs entirely locally.

Best regards,
Mayank Chugh
+852-64851129

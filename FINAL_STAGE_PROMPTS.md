# FINAL_STAGE_PROMPTS.md
## andela-security-auditor — Final 3 Prompts
## Use these after the MVP is built and tests are passing

---

## PROMPT 1 — END-TO-END TEST

```
Start the FastAPI server on port 8000 and Streamlit dashboard on port 8501.
Scan all 3 sample config files — clean_infra.tf, vulnerable_infra.tf, and
mixed_infra.yaml — using the POST /scan endpoint.
Report the risk score for each file.
Expected results:
- clean_infra.tf → score 0 (no violations)
- vulnerable_infra.tf → score 100 (capped — multiple critical/high findings)
- mixed_infra.yaml → score between 40-65 (2 violations)
Fix any issues found during the end-to-end run.
Update SESSION_HANDOVER.md stage tracker — tick all completed items.
Update prompts.md. Report elapsed time.
```

---

## PROMPT 2 — SECURITY HARDENING

```
Security hardening pass — implement all controls from SECURITY_AND_PII.md:

1. Filename sanitisation in POST /scan before saving temp file
   (strip non-alphanumeric except . _ - , max 255 chars)
2. File type whitelist — reject anything that is not .tf, .yaml, or .yml
3. File size limit — reject files over 10MB
4. Temp file cleanup — wrap in try/finally so file is always deleted
5. Security headers middleware in app/main.py:
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   X-XSS-Protection: 1; mode=block
6. HARDCODED_SECRET rule — detect hardcoded passwords/keys in .tf files
   but NEVER store the actual value — description must say "Value redacted"
7. Ensure no raw file content is ever stored in SQLite
8. Clean error messages on all endpoints — no stack traces in API responses

After implementing each control, tick the corresponding checkbox in
SECURITY_AND_PII.md under "PII controls" section.
Run all tests again — all must still pass.
Update prompts.md. Report elapsed time.
```

---

## PROMPT 3 — FINAL POLISH + PUSH

```
Final tasks — complete all submission requirements:

1. Complete README.md with:
   - Title and Python/FastAPI/Streamlit/SQLite badges
   - ASCII architecture diagram:
     [.tf/.yaml files] -> [Scanner] -> [Rules Engine] -> [Risk Scorer]
     -> [SQLite DB] -> [FastAPI REST API] -> [Streamlit Dashboard]
   - Security rules table (all 8 rules, severity, points, description)
   - Risk score legend (0=Clean, 1-25=Low, 26-50=Medium, 51-75=High, 76-100=Critical)
   - Quick start: pip install -r requirements.txt then uvicorn and streamlit commands
   - API reference table (method, endpoint, description)
   - Tech stack table
   - About the architect:
     "Built by Mayank Chugh — Senior Enterprise Architect with 20+ years delivering
     technology at Cathay Pacific, HSBC, British Airways, CHANEL, and M&S.
     HashiCorp Terraform Associate certified. Andela FDE candidate.
     Tagle.ai AI Readiness Type: The Connector (Navigator edge) — Confident Operator stage."

2. Complete presentation.md (Marp-compatible Markdown):
   Slide 1: Title — Enterprise Security Guardrail Auditor | Mayank Chugh | Andela FDE
   Slide 2: The Problem — cloud misconfigs are the #1 cause of enterprise data breaches
   Slide 3: Solution Architecture (ASCII diagram)
   Slide 4: Security Rules & Risk Scoring Algorithm (table)
   Slide 5: Tech Stack (table)
   Slide 6: Key Features — scanner, REST API, dashboard, audit trail, PII controls
   Slide 7: Vibe Coding Workflow — architect directs, AI executes, prompts.md audits everything
   Slide 8: About the Architect — Mayank Chugh, 20+ years, Terraform certified, The Connector

3. Verify tagle_tag.png exists in repo root (Mayank will add manually if not)

4. Run all tests one final time — all must pass

5. Update SESSION_HANDOVER.md — mark all stages complete

6. Update prompts.md — verify complete audit log

7. Provide these exact git commands to push everything:
   git add .
   git commit -m "feat: complete Enterprise Security Guardrail Auditor — Andela FDE challenge submission"
   git push origin main

Report TOTAL elapsed time for the complete project.
```

---

## AFTER PUSH — MAKE REPO PUBLIC

In GitHub:
Settings → General → Danger Zone → Change visibility → Make public

---

## SUBMISSION EMAIL

Send to: florencia.vattino@andela.com
CC: guilherme.pompeo@andela.com

Subject: Andela FDE Technical Challenge Submission — Mayank Chugh

```
Hi Florencia and Guilherme,

Please find my technical challenge submission below.

Project: Enterprise Security Guardrail Auditor (Project 2 — Compliance Focus)
GitHub: https://github.com/mayankchugh-learning/andela-security-auditor
Tagle.ai Tag: The Connector (Navigator edge) | Confident Operator stage

Deliverables in the repository:
- Full source code — Python, FastAPI, Streamlit, SQLite
- prompts.md — complete AI prompt audit log (vibe coding workflow)
- README.md — architecture, security rules, quick start guide
- presentation.md — 8-slide solution deck
- tagle_tag.png — Tagle.ai assessment result

Project highlights:
- 11 security rules covering CIS Benchmark violations
- Weighted risk scoring algorithm (0-100)
- Full PII controls — no secrets stored, temp files always deleted
- 19 automated tests — all passing
- Runs entirely locally — no cloud resources provisioned

Best regards,
Mayank Chugh
+852-64851129
mayankchugh.jobathk@gmail.com
```

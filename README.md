# Enterprise Security Guardrail Auditor

**Andela Senior GenAI Engineer (FDE) Technical Challenge**
**Candidate:** Mayank Chugh | 20+ years enterprise delivery | HashiCorp Terraform Associate Certified

[![Tests](https://img.shields.io/badge/tests-29%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

---

## What It Does

A Python-based, API-first **Enterprise Security Guardrail Auditor** that:

- Scans **Terraform (`.tf`)** and **CloudFormation (`.yaml`)** infrastructure config files
- Detects **11 security misconfigurations** against CIS Benchmark-inspired rules
- Calculates a **weighted Risk Score** (0–100) with severity-based band labels
- Stores full scan history in **SQLite** (zero setup, no cloud needed)
- Exposes findings via a **FastAPI REST API** with OpenAPI docs
- Visualises results in a **Streamlit dashboard** with colour-coded severity
- Enforces **security hardening** — rate limiting, filename sanitisation, security headers, value redaction, temp file cleanup

---

## ASCII Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      Streamlit Dashboard                         │
│                   dashboard/app.py  :8501                        │
│   [ Upload .tf/.yaml ] → [ Risk Score ] → [ Findings Table ]     │
│   [ Scan History ]  →  [ Select Scan ] → [ Full Details ]        │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTP POST /scan
                             │ HTTP GET  /scans, /scans/{id}
┌────────────────────────────▼─────────────────────────────────────┐
│                    FastAPI REST API  :8000                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │              Security Middleware Layer                  │     │
│  │  • Rate limiting (slowapi 10/min per IP)                │     │
│  │  • Filename sanitisation  • 10 MB size limit            │     │
│  │  • Security headers (X-Frame, X-XSS, Referrer-Policy)  │     │
│  │  • Temp file cleanup (try/finally)                      │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  POST /scan   GET /scans   GET /scans/{id}   GET /health         │
└──────┬──────────────────────────────────────────┬───────────────┘
       │                                          │
┌──────▼────────────┐                  ┌──────────▼──────────────┐
│   Parser Layer    │                  │    SQLite Database       │
│                   │                  │   (SQLAlchemy ORM)       │
│  hcl_parser.py    │                  │                          │
│  • python-hcl2    │                  │   scans table            │
│  • _unquote() fix │                  │   findings table         │
│                   │                  │                          │
│  cf_parser.py     │                  │  No raw file content     │
│  • pyyaml         │                  │  No secret values stored │
│  • !Ref tag fix   │                  └─────────────────────────┘
└──────┬────────────┘
       │ flat resource list
┌──────▼────────────┐
│   Rules Engine    │
│   engine.py       │
│                   │
│   11 CIS rules:   │
│   2 × Critical    │
│   5 × High        │
│   4 × Medium      │
└──────┬────────────┘
       │ findings list
┌──────▼────────────┐
│   Risk Scorer     │
│   risk_score.py   │
│                   │
│   score = min(    │
│     Σpoints, 100) │
└───────────────────┘
```

---

## Security Rules (11 total)

| Rule ID | Severity | Points | Trigger |
|---|---|---|---|
| PUBLIC_S3_BUCKET | 🔴 Critical | 40 | S3 bucket ACL = public-read / public-read-write |
| OPEN_ALL_PORTS | 🔴 Critical | 40 | Security group protocol=-1 open to 0.0.0.0/0 |
| OPEN_SSH | 🟠 High | 25 | Port 22 open to 0.0.0.0/0 |
| OPEN_RDP | 🟠 High | 25 | Port 3389 open to 0.0.0.0/0 |
| UNENCRYPTED_EBS | 🟠 High | 25 | EBS volume encrypted = false |
| UNENCRYPTED_RDS | 🟠 High | 25 | RDS instance storage_encrypted = false |
| HARDCODED_SECRET | 🟠 High | 25 | Literal value in password / secret / api_key / access_key attribute |
| NO_MFA | 🟡 Medium | 20 | IAM user with login_profile but no MFA policy |
| WEAK_IAM_POLICY | 🟡 Medium | 20 | IAM policy with Action: "*" wildcard |
| HTTP_LISTENER | 🟡 Medium | 20 | Load balancer listener protocol = HTTP |
| UNRESTRICTED_OUTBOUND | 🟡 Medium | 20 | Security group egress open to 0.0.0.0/0 |

**Risk Score** = `min(sum of finding points, 100)`

| Score | Band |
|---|---|
| 0 | ✅ Clean |
| 1 – 25 | 🟢 Low Risk |
| 26 – 50 | 🟡 Medium Risk |
| 51 – 75 | 🟠 High Risk |
| 76 – 100 | 🔴 Critical Risk |

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Language | Python 3.11+ | Type hints throughout |
| API | FastAPI + Uvicorn | Auto OpenAPI docs at /docs |
| Database | SQLite via SQLAlchemy 2.x | Zero setup, file-based |
| HCL Parser | python-hcl2 | Handles Terraform 0.12+ |
| YAML Parser | pyyaml | Custom CF intrinsic tag loader |
| Dashboard | Streamlit | Single-file, no React needed |
| Rate Limiting | slowapi | 10 scans/minute per IP |
| Testing | pytest | 29 tests across 4 suites |

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/mayankchugh-learning/andela-security-auditor.git
cd andela-security-auditor
```

### 2. Create and activate a virtual environment

**Using uv (recommended — faster):**
```bash
uv init
uv venv
```

Windows:
```bash
.venv\Scripts\activate
```

Mac/Linux:
```bash
source venv/bin/activate
```

**Using standard Python (alternative):**
```bash
python -m venv venv
```
Then activate as above.

### 3. Install dependencies

> **Windows note:** Requires Python 3.11+. numpy 2.x is installed automatically — no C compiler needed.

```bash
uv pip install -r requirements.txt
```

Or with standard pip:
```bash
pip install -r requirements.txt
```

### 4. Start the API

```bash
uvicorn app.main:app --reload --port 8000
```

Browse to **http://localhost:8000/docs** for the interactive OpenAPI UI.

### 5. Start the dashboard (new terminal — activate venv first)

Windows:
```bash
venv\Scripts\activate
streamlit run dashboard/app.py --server.port 8501
```

Mac/Linux:
```bash
source venv/bin/activate
streamlit run dashboard/app.py --server.port 8501
```

Browse to **http://localhost:8501**

### 4. Scan a sample file

```bash
# Vulnerable Terraform — expect score 100, Critical Risk
curl -X POST http://localhost:8000/scan \
  -F "file=@sample_configs/vulnerable_infra.tf"

# Clean Terraform — expect score 0, Clean
curl -X POST http://localhost:8000/scan \
  -F "file=@sample_configs/clean_infra.tf"

# Mixed CloudFormation — expect score 45, Medium Risk
curl -X POST http://localhost:8000/scan \
  -F "file=@sample_configs/mixed_infra.yaml"
```

### 5. Run all tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
# Expected: 29 passed
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check — returns `{"status": "ok"}` |
| `POST` | `/scan` | Upload `.tf` / `.yaml` — returns findings + risk score |
| `GET` | `/scans` | List all past scans (newest first) |
| `GET` | `/scans/{scan_id}` | Full findings for a specific scan |
| `GET` | `/docs` | Interactive OpenAPI UI (auto-generated) |

**POST /scan — example response:**
```json
{
  "scan_id": 1,
  "filename": "vulnerable_infra.tf",
  "file_type": "tf",
  "risk_score": 100,
  "risk_level": "Critical Risk",
  "total_findings": 6,
  "findings": [
    {
      "rule_id": "PUBLIC_S3_BUCKET",
      "severity": "Critical",
      "points": 40,
      "description": "S3 bucket has public read/write access enabled...",
      "resource": "public_bucket"
    }
  ]
}
```

---

## Security Hardening

The API implements production-grade security controls:

| Control | Implementation |
|---|---|
| Filename sanitisation | `re.sub(r'[^a-zA-Z0-9._-]', '_', name)[:255]` |
| File type whitelist | `.tf`, `.yaml`, `.yml`, `.json` only |
| File size limit | 10 MB max — HTTP 413 if exceeded |
| Temp file cleanup | `try/finally` + `os.unlink()` |
| Rate limiting | `slowapi` — 10 scans/minute per client IP |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy` |
| Secret value redaction | `HARDCODED_SECRET` findings never store the actual secret value |
| Clean error responses | No stack traces exposed in API responses |

---

## Sample Configs

| File | Expected Score | Violations |
|---|---|---|
| `sample_configs/clean_infra.tf` | 0 — Clean | None |
| `sample_configs/vulnerable_infra.tf` | 100 — Critical Risk | PUBLIC_S3_BUCKET, OPEN_SSH, OPEN_RDP, OPEN_ALL_PORTS, UNENCRYPTED_EBS, HTTP_LISTENER |
| `sample_configs/mixed_infra.yaml` | 45 — Medium Risk | OPEN_SSH, HTTP_LISTENER |

---

## Project Structure

```
andela-security-auditor/
├── app/
│   ├── main.py                 # FastAPI app + security headers middleware
│   ├── scanner/
│   │   ├── hcl_parser.py       # Terraform .tf parser (hcl2 v8 unquoting fix)
│   │   └── cf_parser.py        # CloudFormation .yaml parser (!Ref tag fix)
│   ├── rules/
│   │   ├── definitions.py      # 11 security rule definitions
│   │   └── engine.py           # Rules engine — TF + CF resource types
│   ├── scoring/
│   │   └── risk_score.py       # Weighted risk scoring (0–100)
│   ├── database/
│   │   ├── models.py           # SQLAlchemy Scan + Finding models
│   │   └── session.py          # DB session management
│   └── api/
│       └── routes.py           # FastAPI route handlers + security controls
├── dashboard/
│   └── app.py                  # Streamlit dashboard
├── sample_configs/
│   ├── clean_infra.tf          # Zero violations
│   ├── vulnerable_infra.tf     # 6 violations → score 100
│   └── mixed_infra.yaml        # 2 violations → score 45
├── tests/
│   ├── test_scanner.py         # Parser tests
│   ├── test_rules.py           # Rules engine + scoring tests
│   ├── test_api.py             # API endpoint tests
│   └── test_security.py        # Security hardening tests
├── CLAUDE.md                   # AI coding rules
├── SECURITY_AND_PII.md         # Security controls specification
├── prompts.md                  # Full AI prompt audit log
├── presentation.md             # Submission deck
├── requirements.txt
└── requirements-dev.txt
```

---

## Candidate Background

| | |
|---|---|
| Experience | 20+ years enterprise technology delivery |
| Certification | **HashiCorp Terraform Associate** — directly relevant to this project |
| Enterprise clients | Cathay Pacific, HSBC, CHANEL, British Airways |
| Certifications | 12 total: AZ-400, TOGAF 9.2, AWS Solutions Architect, and more |
| AI applications | 6 live deployed AI applications |
| Availability | HK Permanent Resident — immediately available |

---

## No Cloud Resources

Everything runs locally. SQLite database lives in `security_auditor.db` (git-ignored). No AWS, Azure, or GCP accounts required.

---

*Built with Claude Code (claude-sonnet-4-6) — vibe coding, architect-led*
*Andela Senior GenAI Engineer (FDE) Technical Challenge — Mayank Chugh*

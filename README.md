# Enterprise Security Guardrail Auditor

**Andela Senior GenAI Engineer (FDE) Technical Challenge**
**Candidate:** Mayank Chugh | 20+ years enterprise delivery | HashiCorp Terraform Associate Certified

---

## What It Does

A Python-based, API-first tool that scans Terraform (`.tf`) and CloudFormation (`.yaml`) infrastructure config files for security misconfigurations against CIS Benchmark-inspired rules, calculates a weighted Risk Score, stores scan history in SQLite, and visualises findings in a Streamlit dashboard.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Streamlit Dashboard                │
│              dashboard/app.py (port 8501)           │
└────────────────────────┬────────────────────────────┘
                         │ HTTP
┌────────────────────────▼────────────────────────────┐
│              FastAPI REST API (port 8000)            │
│  POST /scan  GET /scans  GET /scans/{id}  GET /health│
└──┬───────────────────────────────────────────────┬──┘
   │                                               │
┌──▼──────────────┐                    ┌───────────▼──────┐
│  Parser Layer   │                    │  SQLite Database  │
│  hcl_parser.py  │                    │  (SQLAlchemy ORM) │
│  cf_parser.py   │                    └──────────────────┘
└──┬──────────────┘
   │
┌──▼──────────────┐
│  Rules Engine   │
│  8 CIS rules    │
└──┬──────────────┘
   │
┌──▼──────────────┐
│  Risk Scorer    │
│  0–100 score    │
└─────────────────┘
```

---

## Security Rules

| Rule ID | Severity | Points | Description |
|---|---|---|---|
| PUBLIC_S3_BUCKET | Critical | 40 | S3 bucket with public ACL |
| OPEN_SSH | High | 25 | Port 22 open to 0.0.0.0/0 |
| OPEN_RDP | High | 25 | Port 3389 open to 0.0.0.0/0 |
| OPEN_ALL_PORTS | Critical | 40 | All ports open to 0.0.0.0/0 |
| NO_MFA | Medium | 20 | IAM user without MFA enforced |
| WEAK_IAM_POLICY | Medium | 20 | IAM policy with wildcard * actions |
| UNENCRYPTED_EBS | High | 25 | EBS volume with encryption disabled |
| HTTP_LISTENER | Medium | 20 | Load balancer with HTTP (not HTTPS) |

**Risk Score** = min(sum of finding points, 100)
- 0 = Clean | 1–25 = Low | 26–50 = Medium | 51–75 = High | 76–100 = Critical

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| API | FastAPI + Uvicorn |
| Database | SQLite via SQLAlchemy |
| HCL Parser | python-hcl2 |
| YAML Parser | pyyaml |
| Dashboard | Streamlit |
| Validation | Pydantic v2 |
| Testing | pytest |

---

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the API server

```bash
uvicorn app.main:app --reload --port 8000
```

### 3. Start the dashboard (new terminal)

```bash
streamlit run dashboard/app.py
```

### 4. Run tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

### 5. Try the sample configs

```bash
# Via curl
curl -X POST http://localhost:8000/scan \
  -F "file=@sample_configs/vulnerable_infra.tf"

# Via API docs
open http://localhost:8000/docs
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | /scan | Upload .tf or .yaml, returns findings + risk score |
| GET | /scans | List all past scans |
| GET | /scans/{scan_id} | Get full findings for a scan |
| GET | /health | Health check |
| GET | /docs | OpenAPI documentation (auto) |

---

## Candidate Background

- 20+ years enterprise technology delivery
- **HashiCorp Terraform Associate** — certified (directly relevant to this project)
- Regulated-industry delivery: Cathay Pacific, HSBC, CHANEL, British Airways
- 12 industry certifications: AZ-400, TOGAF 9.2, AWS SA, and more
- 6 live deployed AI applications
- HK Permanent Resident — available immediately

---

## No Cloud Resources Required

Everything runs locally. SQLite stores scan history in `security_auditor.db`. No AWS/Azure accounts needed.

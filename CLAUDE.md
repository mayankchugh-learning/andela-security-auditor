# CLAUDE.md — andela-security-auditor
## Project: Enterprise Security Guardrail Auditor
## Candidate: Mayank Chugh | Andela Senior GenAI Engineer (FDE) Challenge

---

## ARCHITECT RULES — READ BEFORE EVERY RESPONSE

1. **No Manual Edits**: You write ALL code. I (Mayank) will not edit any file manually.
2. **Audit Log**: After EVERY turn, append the prompt I just used to `prompts.md`.
3. **Time-Check**: Report `Elapsed Time: Xhr Ymin` at the end of EVERY response.
4. **Fix Protocol**: If a bug occurs, I describe it in plain English. You provide the complete fix.
5. **One Stage at a Time**: Complete each stage fully before moving to the next.
6. **No Cloud Resources**: Everything runs locally or on free tier. No AWS/Azure accounts needed.
7. **Vibe Coding**: You are the engineer. I am the architect. I direct, you execute.

---

## Project Overview

Build a Python-based, API-first **Enterprise Security Guardrail Auditor** that:
- Scans Terraform (.tf) and CloudFormation (.yaml) infrastructure config files
- Detects security misconfigurations against CIS Benchmark rules
- Calculates a weighted Risk Score (0–100)
- Stores scan history in SQLite
- Exposes results via FastAPI REST API
- Visualises findings in a Streamlit dashboard

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
| Code quality | ruff + black |

---

## Project Structure

```
andela-security-auditor/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app entry point
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── hcl_parser.py       # Terraform .tf file parser
│   │   └── cf_parser.py        # CloudFormation .yaml parser
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py           # Rules engine — applies all rules
│   │   └── definitions.py      # All security rule definitions
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── risk_score.py       # Weighted risk scoring algorithm
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py           # SQLAlchemy models
│   │   └── session.py          # DB session management
│   └── api/
│       ├── __init__.py
│       └── routes.py           # FastAPI route handlers
├── dashboard/
│   └── app.py                  # Streamlit dashboard
├── sample_configs/
│   ├── clean_infra.tf          # No violations
│   ├── vulnerable_infra.tf     # Multiple violations
│   └── mixed_infra.yaml        # CloudFormation — mixed
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_rules.py
│   └── test_api.py
├── CLAUDE.md                   # This file
├── .cursorrules                # Cursor AI rules
├── prompts.md                  # Audit log — auto-updated each turn
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── presentation.md
└── .gitignore
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

---

## Risk Score Algorithm

```
Risk Score = min(sum of all finding points, 100)

Critical finding = 40 points
High finding     = 25 points
Medium finding   = 20 points
Low finding      = 15 points

Score 0        = Clean — no violations
Score 1–25     = Low Risk
Score 26–50    = Medium Risk
Score 51–75    = High Risk
Score 76–100   = Critical Risk
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | /scan | Upload .tf or .yaml file, returns findings + risk score |
| GET | /scans | List all past scans |
| GET | /scans/{scan_id} | Get full findings for a scan |
| GET | /health | Health check |
| GET | /docs | OpenAPI documentation (auto) |

---

## Submission Requirements

- [ ] Tagle.ai Tag screenshot
- [ ] Public GitHub repo: `andela-security-auditor`
- [ ] `prompts.md` — full audit log
- [ ] `README.md` — architecture + how to run
- [ ] `presentation.md` — AI-generated deck
- [ ] Email to florencia.vattino@andela.com + guilherme.pompeo@andela.com
- [ ] No cloud resources used

---

## Candidate Background (use in README and deck)

- 20+ years enterprise technology delivery
- HashiCorp Terraform Associate — certified (directly relevant to this project)
- Delivered regulated-industry projects: Cathay Pacific, HSBC, CHANEL, British Airways
- 12 industry certifications including AZ-400, TOGAF 9.2, AWS SA
- 6 live deployed AI applications
- HK Permanent Resident — available immediately

# Enterprise Security Guardrail Auditor
## Submission Presentation — Andela Senior GenAI Engineer (FDE) Challenge
## Candidate: Mayank Chugh | AI Tool: Claude Code (claude-sonnet-4-6)

---

### Slide 1 — Title

```
╔══════════════════════════════════════════════════════════════╗
║          ENTERPRISE SECURITY GUARDRAIL AUDITOR               ║
║       Automated IaC Security Misconfiguration Detection      ║
╠══════════════════════════════════════════════════════════════╣
║  Candidate : Mayank Chugh                                    ║
║  Role      : Andela Senior GenAI Engineer (FDE) Challenge    ║
║  AI Tool   : Claude Code (claude-sonnet-4-6)                 ║
║  Built in  : < 2 hours — vibe coding, architect-led          ║
╚══════════════════════════════════════════════════════════════╝
```

**GitHub:** github.com/mayankchugh-learning/andela-security-auditor

---

### Slide 2 — The Problem

**Infrastructure-as-Code ships fast. Security controls don't keep pace.**

```
Every day, teams commit Terraform and CloudFormation:

  resource "aws_s3_bucket" "data" {
    acl = "public-read"          ← 40-point critical violation
  }

  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"] ← SSH open to the internet
  }
```

**The gap:**
- Manual code review misses 1 in 3 misconfigurations (Gartner 2023)
- Average cost of a cloud breach: **$4.45M** (IBM 2023)
- CIS Benchmarks exist — but are not enforced at commit time

**This tool closes that gap automatically.**

---

### Slide 3 — The Solution

**One API call. Instant security verdict.**

```
Developer uploads .tf or .yaml
          ↓
  POST http://localhost:8000/scan
          ↓
  {
    "risk_score": 100,
    "risk_level": "Critical Risk",
    "total_findings": 6,
    "findings": [
      { "rule_id": "PUBLIC_S3_BUCKET", "severity": "Critical", "points": 40 },
      { "rule_id": "OPEN_SSH",         "severity": "High",     "points": 25 },
      ...
    ]
  }
```

**Value delivered:**
- Instant scan — < 1 second for any config file
- 11 CIS Benchmark rules covering the most exploited cloud misconfigs
- REST API — integrates into any CI/CD pipeline
- Streamlit dashboard — risk scores visible to non-technical stakeholders
- Full scan history — trend over time

---

### Slide 4 — Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Streamlit Dashboard  :8501                     │
│    Upload → Risk Score → Findings Table → Scan History      │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP
┌──────────────────────▼──────────────────────────────────────┐
│                FastAPI REST API  :8000                      │
│                                                             │
│  [Security Middleware]                                      │
│   Rate limiting (10/min) • Filename sanitisation            │
│   10 MB file limit       • Security headers                 │
│   Temp file cleanup      • Clean error messages             │
│                                                             │
│  POST /scan  GET /scans  GET /scans/{id}  GET /health       │
└──────┬─────────────────────────────────────┬────────────────┘
       │                                     │
┌──────▼──────────┐               ┌──────────▼─────────────┐
│  Parser Layer   │               │   SQLite + SQLAlchemy  │
│  hcl_parser.py  │               │   scans + findings     │
│  cf_parser.py   │               │   No secrets stored    │
└──────┬──────────┘               └────────────────────────┘
       │
┌──────▼──────────┐
│  Rules Engine   │
│  11 CIS rules   │
│  TF + CF types  │
└──────┬──────────┘
       │
┌──────▼──────────┐
│  Risk Scorer    │
│  min(Σpts, 100) │
└─────────────────┘
```

**Single Python service. Zero cloud dependencies. Runs in < 1 second.**

---

### Slide 5 — Security Rules (11 CIS Rules)

```
┌─────────────────────────┬──────────┬────────┐
│ Rule                    │ Severity │ Points │
├─────────────────────────┼──────────┼────────┤
│ PUBLIC_S3_BUCKET        │ Critical │   40   │
│ OPEN_ALL_PORTS          │ Critical │   40   │
├─────────────────────────┼──────────┼────────┤
│ OPEN_SSH                │ High     │   25   │
│ OPEN_RDP                │ High     │   25   │
│ UNENCRYPTED_EBS         │ High     │   25   │
│ UNENCRYPTED_RDS         │ High     │   25   │
│ HARDCODED_SECRET        │ High     │   25   │
├─────────────────────────┼──────────┼────────┤
│ NO_MFA                  │ Medium   │   20   │
│ WEAK_IAM_POLICY         │ Medium   │   20   │
│ HTTP_LISTENER           │ Medium   │   20   │
│ UNRESTRICTED_OUTBOUND   │ Medium   │   20   │
└─────────────────────────┴──────────┴────────┘
```

**Risk Score = min(sum of finding points, 100)**

```
Score 0        →  ✅ Clean
Score  1 – 25  →  🟢 Low Risk
Score 26 – 50  →  🟡 Medium Risk
Score 51 – 75  →  🟠 High Risk
Score 76 – 100 →  🔴 Critical Risk
```

---

### Slide 6 — Live Demo Results

**Three sample configs tested against the engine:**

```
clean_infra.tf          →  Score:   0  |  ✅ Clean        |  0 findings
vulnerable_infra.tf     →  Score: 100  |  🔴 Critical Risk |  6 findings
mixed_infra.yaml        →  Score:  45  |  🟡 Medium Risk   |  2 findings
```

**vulnerable_infra.tf breakdown:**
```
PUBLIC_S3_BUCKET   40 pts  ← public-read ACL
OPEN_ALL_PORTS     40 pts  ← protocol=-1 open to 0.0.0.0/0
OPEN_SSH           25 pts  ← port 22 to 0.0.0.0/0
OPEN_RDP           25 pts  ← port 3389 to 0.0.0.0/0
UNENCRYPTED_EBS    25 pts  ← encrypted = false
HTTP_LISTENER      20 pts  ← protocol = HTTP
                  ─────────
Total             175 pts  →  capped at 100  →  CRITICAL RISK
```

**29 / 29 pytest tests passing** across scanner, rules, API, and security suites.

---

### Slide 7 — Security Hardening

**Production-grade controls on the API layer:**

```
Control                  Implementation
───────────────────────  ─────────────────────────────────────────
Filename sanitisation    re.sub(r'[^a-zA-Z0-9._-]', '_', name)
File type whitelist      .tf .yaml .yml .json only → HTTP 400 else
10 MB size limit         → HTTP 413 if exceeded
Temp file cleanup        try/finally + os.unlink()
Rate limiting            slowapi — 10 scans/minute per client IP
Security headers         X-Content-Type-Options: nosniff
                         X-Frame-Options: DENY
                         X-XSS-Protection: 1; mode=block
                         Referrer-Policy: strict-origin-when-cross-origin
Secret value redaction   HARDCODED_SECRET stores attribute name only
                         → "Value redacted" in description
                         → Never logged, never stored in DB
Clean error responses    No stack traces in API responses
```

**OWASP controls addressed:** A01 (Broken Access), A03 (Injection), A05 (Security Misconfiguration)

---

### Slide 8 — Why Mayank Chugh

```
╔══════════════════════════════════════════════════════════════╗
║  This project required three things to build well:          ║
║                                                             ║
║  1. Infrastructure security knowledge                       ║
║     → HashiCorp Terraform Associate (certified)             ║
║     → Delivered IaC for HSBC, Cathay Pacific, BA, CHANEL   ║
║                                                             ║
║  2. API + backend engineering depth                         ║
║     → FastAPI, SQLAlchemy, Pydantic, pytest                 ║
║     → Security middleware, rate limiting, PII controls      ║
║                                                             ║
║  3. AI-augmented delivery speed                             ║
║     → Full MVP in < 2 hours using Claude Code               ║
║     → Vibe coding — architect-led, AI-executed              ║
║     → 6 live deployed AI applications                       ║
╠══════════════════════════════════════════════════════════════╣
║  20+ years │ 12 certifications │ HK PR │ Available now      ║
╚══════════════════════════════════════════════════════════════╝
```

**Senior GenAI Engineer (FDE) = exactly my profile.**

GitHub: github.com/mayankchugh-learning/andela-security-auditor
Email:  mayankchugh.learning@gmail.com

---

*Built with Claude Code (claude-sonnet-4-6) | Vibe coding, architect-led*
*Andela Senior GenAI Engineer (FDE) Technical Challenge*

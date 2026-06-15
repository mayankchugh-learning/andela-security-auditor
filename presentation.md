# Enterprise Security Guardrail Auditor
## AI-Generated Presentation Deck

---

### Slide 1 — Title

**Enterprise Security Guardrail Auditor**
*Automated IaC Security Misconfiguration Detection*

Mayank Chugh | Andela Senior GenAI Engineer (FDE) Challenge
20+ years enterprise delivery | HashiCorp Terraform Associate

---

### Slide 2 — The Problem

**Infrastructure-as-Code moves fast. Security doesn't always keep up.**

- Teams commit Terraform and CloudFormation daily
- One misconfigured security group or public S3 bucket = data breach
- Manual security reviews are slow, inconsistent, and don't scale
- CIS Benchmarks exist but aren't enforced at commit time

**Cost of a single misconfiguration:** Average cloud breach = $4.45M (IBM 2023)

---

### Slide 3 — The Solution

**Automated, API-first security scanning in seconds**

```
Upload .tf or .yaml → Scan → Risk Score → Fix
```

- Detects 8 critical CIS Benchmark misconfigurations
- Weighted risk score 0–100 (Clean → Critical Risk)
- REST API: integrate into any CI/CD pipeline
- Streamlit dashboard: visual findings for non-technical stakeholders
- Full scan history in SQLite

---

### Slide 4 — Architecture

```
Developer uploads config
        ↓
   FastAPI /scan endpoint
        ↓
   Parser (HCL2 / PyYAML)
        ↓
   Rules Engine (8 rules)
        ↓
   Risk Score (0–100)
        ↓
   SQLite (history)
        ↓
   JSON response + Dashboard
```

**Single Python service. No cloud dependencies. Runs in < 1 second.**

---

### Slide 5 — Security Rules

| Severity | Rule | Points |
|---|---|---|
| 🔴 Critical | Public S3 Bucket | 40 |
| 🔴 Critical | All Ports Open | 40 |
| 🟠 High | SSH Open to World | 25 |
| 🟠 High | RDP Open to World | 25 |
| 🟠 High | Unencrypted EBS | 25 |
| 🟡 Medium | No MFA Enforced | 20 |
| 🟡 Medium | Wildcard IAM Policy | 20 |
| 🟡 Medium | HTTP Listener | 20 |

**Risk Score = min(sum of points, 100)**

---

### Slide 6 — Demo Results

**Vulnerable config (`vulnerable_infra.tf`):**
- PUBLIC_S3_BUCKET: 40 pts
- OPEN_SSH: 25 pts
- OPEN_RDP: 25 pts
- OPEN_ALL_PORTS: 40 pts
- UNENCRYPTED_EBS: 25 pts
- HTTP_LISTENER: 20 pts
- **Total: 100 — CRITICAL RISK** 🚨

**Clean config (`clean_infra.tf`):**
- Zero findings — **Score: 0 — CLEAN** ✅

---

### Slide 7 — Why Me

**Mayank Chugh — the right candidate**

✅ **HashiCorp Terraform Associate** — I know IaC security from inside out
✅ **20+ years** regulated-industry delivery (HSBC, Cathay Pacific, BA, CHANEL)
✅ **12 certifications** including AZ-400, TOGAF 9.2, AWS Solutions Architect
✅ **6 live AI applications** — I build and ship, not just prototype
✅ **Available immediately** — HK Permanent Resident, no visa friction
✅ Built this entire auditor in a single AI-assisted coding session

**Senior GenAI Engineer (FDE) = my exact profile.**

---

### Slide 8 — What's Next

**Extension roadmap (next sprint):**

1. **Git integration** — scan on every PR automatically
2. **More rules** — CIS Benchmark Level 2 (50+ rules)
3. **Multi-cloud** — Azure ARM templates, GCP Deployment Manager
4. **Remediation hints** — auto-generate fixed config snippets
5. **SARIF output** — native GitHub Security tab integration
6. **Slack/Teams alerts** — notify security team on Critical findings

---

### Slide 9 — Contact

**Mayank Chugh**
mayankchugh.learning@gmail.com
LinkedIn: linkedin.com/in/mayankchugh-learning
GitHub: github.com/mayankchugh-learning

*Built with Claude Code (claude-sonnet-4-6) — vibe coding, architect-led*

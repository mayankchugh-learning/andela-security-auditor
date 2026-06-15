# SESSION_HANDOVER.md
## Project: Enterprise Security Guardrail Auditor
## Candidate: Mayank Chugh | Andela FDE Challenge
## Purpose: Resume any session instantly in Claude Code OR Cursor

---

## HOW TO USE THIS FILE

**Starting a new session in Claude Code:**
```
Read SESSION_HANDOVER.md fully. You are resuming the andela-security-auditor 
project. Apply all rules from CLAUDE.md. Continue from the current stage below. 
Do not repeat completed work. Update this file and prompts.md after every turn.
```

**Starting a new session in Cursor:**
```
Read SESSION_HANDOVER.md fully. Resume andela-security-auditor from current 
stage. Apply .cursorrules. Do not repeat completed work. Update this file and 
prompts.md after every turn.
```

---

## CURRENT STATUS
> AI must update this section after EVERY turn

```
Last updated:     [AI fills this]
Active tool:      [ ] Claude Code  [ ] Cursor
Current stage:    Stage [X] — [Stage Name]
Current task:     [What is being worked on right now]
Next task:        [What comes immediately after]
Elapsed time:     [Xhr Ymin of 48hr window]
Remaining time:   [Xhr Ymin remaining]
Session started:  [Timestamp when Florencia confirmed]
Deadline:         [Timestamp = session start + 48hrs]
```

---

## STAGE COMPLETION TRACKER
> AI must tick each item when complete

### Stage 0 — Kickoff
- [ ] CLAUDE.md read and acknowledged
- [ ] Timer started
- [ ] prompts.md initialised

### Stage 1 — Project Scaffold
- [ ] Directory structure created
- [ ] All __init__.py files created
- [ ] app/main.py placeholder created
- [ ] requirements.txt complete
- [ ] .gitignore created
- [ ] README.md placeholder created
- [ ] prompts.md updated

### Stage 2 — Sample Config Files
- [ ] clean_infra.tf created (no violations)
- [ ] vulnerable_infra.tf created (5 violations)
- [ ] mixed_infra.yaml created (2 violations, 2 clean)
- [ ] All files syntactically valid
- [ ] prompts.md updated

### Stage 3 — Scanner + Rules Engine
- [ ] app/scanner/hcl_parser.py — parse_terraform() working
- [ ] app/scanner/cf_parser.py — parse_cloudformation() working
- [ ] app/rules/definitions.py — all 8 rules defined
- [ ] app/rules/engine.py — run_rules() working
- [ ] Tested against all 3 sample files
- [ ] prompts.md updated

### Stage 4 — Risk Scoring + Database
- [ ] app/scoring/risk_score.py — calculate_risk_score() working
- [ ] app/database/models.py — ScanResult + Finding models created
- [ ] app/database/session.py — engine + session factory working
- [ ] Database creates on startup
- [ ] Risk scores verified against sample files
- [ ] prompts.md updated

### Stage 5 — FastAPI Layer
- [ ] POST /scan working
- [ ] GET /scans working
- [ ] GET /scans/{scan_id} working
- [ ] GET /health working
- [ ] app/api/schemas.py — all Pydantic models defined
- [ ] /docs OpenAPI UI accessible
- [ ] CORS configured
- [ ] All endpoints tested with sample files
- [ ] prompts.md updated

### Stage 6 — Streamlit Dashboard
- [ ] dashboard/app.py created
- [ ] File uploader working
- [ ] Risk score display with colour coding
- [ ] Findings table with severity badges
- [ ] Scan history section
- [ ] Empty state handled
- [ ] End-to-end test: upload file → see results
- [ ] prompts.md updated

### Stage 7 — README + Presentation
- [ ] README.md complete with all sections
- [ ] ASCII architecture diagram included
- [ ] presentation.md complete (8 slides)
- [ ] prompts.md updated

### Stage 8 — Tests + Polish + Push
- [ ] tests/test_scanner.py passing
- [ ] tests/test_rules.py passing
- [ ] tests/test_api.py passing
- [ ] Full end-to-end run completed
- [ ] Risk scores verified: clean=0, vulnerable=100, mixed=40-65
- [ ] prompts.md final audit log complete
- [ ] Git commands executed
- [ ] Repo pushed to GitHub
- [ ] Total elapsed time recorded

### Submission
- [ ] Tagle.ai assessment completed
- [ ] Tag screenshot saved
- [ ] GitHub repo public and accessible
- [ ] Submission email sent to Florencia + Guilherme

---

## BACKLOG
> AI maintains this. Items added when discovered during development.
> Priority: P1 (must do), P2 (should do), P3 (nice to have)

### Active backlog items
| ID | Priority | Item | Stage | Status |
|---|---|---|---|---|
| BL-001 | P1 | Add input file size limit (max 10MB) | Stage 5 | Pending |
| BL-002 | P1 | Add file type validation (reject non .tf/.yaml) | Stage 5 | Pending |
| BL-003 | P1 | PII scrubbing in scan results before DB storage | Stage 4 | Pending |
| BL-004 | P1 | Rate limiting on /scan endpoint | Stage 5 | Pending |
| BL-005 | P2 | Add CloudFormation JSON support (.json) | Stage 3 | Pending |
| BL-006 | P2 | Export findings as PDF report | Stage 6 | Pending |
| BL-007 | P2 | Add scan comparison (before/after) | Stage 6 | Pending |
| BL-008 | P3 | Dark mode for dashboard | Stage 6 | Pending |
| BL-009 | P3 | Bulk scan (multiple files at once) | Stage 5 | Pending |

### Completed backlog items
| ID | Priority | Item | Completed in stage |
|---|---|---|---|
| — | — | — | — |

---

## ERROR LOG
> AI logs every bug and fix here. Never delete entries.

| # | Stage | Error description | Fix applied | Status |
|---|---|---|---|---|
| — | — | No errors yet | — | — |

---

## DECISIONS LOG
> AI logs every architectural decision here with rationale.

| # | Decision | Rationale | Alternative considered |
|---|---|---|---|
| D-001 | SQLite over PostgreSQL | Zero setup, free tier, sufficient for demo | PostgreSQL (overkill for challenge scope) |
| D-002 | Streamlit over React | Single file, fast to build, looks professional | React+FastAPI (too slow to build in time) |
| D-003 | python-hcl2 for Terraform | Most reliable HCL parser in Python ecosystem | Manual regex parsing (error-prone) |
| D-004 | File upload over API key | Simpler UX, no auth complexity for demo | Token-based auth (adds complexity) |
| D-005 | Local deployment over cloud | Zero cost, no cloud bills, meets challenge requirement | HuggingFace Spaces (backup option) |

---

## KNOWN LIMITATIONS
> Document honestly — evaluators respect transparency

- Scanner handles HCL2 format only (Terraform 0.12+). Legacy HCL1 not supported.
- CloudFormation supports YAML only. JSON CloudFormation templates not yet supported.
- Risk score caps at 100 — multiple critical findings still score 100.
- No authentication on API endpoints (not required for demo scope).
- SQLite resets if server restarts (acceptable for challenge demo).

---

## SECURITY & PII IMPLEMENTATION STATUS

### Cybersecurity rules implemented in scanner
| Rule ID | Severity | Status |
|---|---|---|
| PUBLIC_S3_BUCKET | Critical | [ ] Pending |
| OPEN_SSH | High | [ ] Pending |
| OPEN_RDP | High | [ ] Pending |
| OPEN_ALL_PORTS | Critical | [ ] Pending |
| NO_MFA | Medium | [ ] Pending |
| WEAK_IAM_POLICY | Medium | [ ] Pending |
| UNENCRYPTED_EBS | High | [ ] Pending |
| HTTP_LISTENER | Medium | [ ] Pending |

### PII handling implemented
| Control | Location | Status |
|---|---|---|
| Filename sanitisation | POST /scan | [ ] Pending |
| No credentials stored in DB | app/database/models.py | [ ] Pending |
| Temp file cleanup after scan | POST /scan | [ ] Pending |
| No PII in logs | All logging calls | [ ] Pending |
| Input size limit (10MB) | POST /scan | [ ] Pending |
| File type whitelist | POST /scan | [ ] Pending |

---

## QUICK REFERENCE

### Start the application
```bash
# Terminal 1 — FastAPI
uvicorn app.main:app --reload --port 8000

# Terminal 2 — Streamlit
streamlit run dashboard/app.py --server.port 8501
```

### Run tests
```bash
pytest tests/ -v
```

### Check linting
```bash
ruff check .
black --check .
```

### Push to GitHub
```bash
git add .
git commit -m "feat: [describe what was done]"
git push origin main
```

---

## SUBMISSION CHECKLIST (final gate)
- [ ] Tagle.ai Tag screenshot saved as tagle_tag.png in repo root
- [ ] GitHub repo is PUBLIC: github.com/mayankchugh-learning/andela-security-auditor
- [ ] prompts.md has all turns logged
- [ ] README.md is complete
- [ ] presentation.md is complete
- [ ] All tests passing
- [ ] Application runs end-to-end locally
- [ ] No cloud resources provisioned
- [ ] Submission email sent

---

*This file is maintained by the AI agent. Mayank does not edit this file manually.*

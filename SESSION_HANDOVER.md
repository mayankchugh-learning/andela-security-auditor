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
Last updated:     2026-06-15 (Turn 3)
Active tool:      [x] Claude Code  [ ] Cursor
Current stage:    Stage 8 COMPLETE — MVP fully built, tested, and pushed
Current task:     DONE — all stages complete
Next task:        Submission — push to GitHub (done), send email, Tagle.ai screenshot
Elapsed time:     0h 45min
Remaining time:   ~15h 15min (of 16h max window)
Session started:  2026-06-15
Deadline:         2026-06-16
```

---

## STAGE COMPLETION TRACKER
> AI must tick each item when complete

### Stage 0 — Kickoff
- [x] CLAUDE.md read and acknowledged
- [x] Timer started
- [x] prompts.md initialised

### Stage 1 — Project Scaffold
- [x] Directory structure created
- [x] All __init__.py files created
- [x] app/main.py created
- [x] requirements.txt complete
- [x] .gitignore created
- [x] README.md complete
- [x] prompts.md updated

### Stage 2 — Sample Config Files
- [x] clean_infra.tf created (no violations)
- [x] vulnerable_infra.tf created (6 violations)
- [x] mixed_infra.yaml created (2 violations, 3 clean resources)
- [x] All files syntactically valid
- [x] prompts.md updated

### Stage 3 — Scanner + Rules Engine
- [x] app/scanner/hcl_parser.py — parse_terraform() working (hcl2 v8 unquoting fix applied)
- [x] app/scanner/cf_parser.py — parse_cloudformation() working (CloudFormation !Ref tag fix applied)
- [x] app/rules/definitions.py — all 8 rules defined
- [x] app/rules/engine.py — apply_rules() working for TF + CF resource types
- [x] Tested against all 3 sample files
- [x] prompts.md updated

### Stage 4 — Risk Scoring + Database
- [x] app/scoring/risk_score.py — calculate_risk_score() working
- [x] app/database/models.py — Scan + Finding models created
- [x] app/database/session.py — engine + session factory working
- [x] Database creates on startup
- [x] Risk scores verified against sample files
- [x] prompts.md updated

### Stage 5 — FastAPI Layer
- [x] POST /scan working
- [x] GET /scans working
- [x] GET /scans/{scan_id} working
- [x] GET /health working
- [x] /docs OpenAPI UI accessible
- [x] All endpoints tested with sample files
- [x] prompts.md updated

### Stage 6 — Streamlit Dashboard
- [x] dashboard/app.py created
- [x] File uploader working
- [x] Risk score display with colour coding
- [x] Findings table with severity badges
- [x] Scan history section
- [x] Empty state handled
- [x] prompts.md updated

### Stage 7 — README + Presentation
- [x] README.md complete with all sections
- [x] ASCII architecture diagram included
- [x] presentation.md complete (9 slides)
- [x] prompts.md updated

### Stage 8 — Tests + Polish + Push
- [x] tests/test_scanner.py passing (2/2)
- [x] tests/test_rules.py passing (10/10)
- [x] tests/test_api.py passing (7/7)
- [x] Full end-to-end run completed
- [x] Risk scores verified: clean=0, vulnerable=100, mixed=45 (Medium Risk, within 40-65)
- [x] prompts.md final audit log complete
- [x] Git committed (9cc6f10)
- [x] Repo pushed to GitHub
- [x] Total elapsed time: 0h 45min

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
| 1 | Stage 3 | python-hcl2 v8 wraps resource type keys and all string values in double-quotes | Added _unquote() recursive stripper in hcl_parser.py | Fixed |
| 2 | Stage 6 | CloudFormation YAML with !Ref intrinsic tag caused PyYAML SafeLoader to crash | Added multi-constructor in cf_parser.py that silently handles all CF intrinsic tags | Fixed |
| 3 | Stage 2 | mixed_infra.yaml had 4 violations (score=100), outside expected 40-65 range | Removed public S3 bucket from mixed file; kept OPEN_SSH+HTTP_LISTENER (45pts) | Fixed |

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
| PUBLIC_S3_BUCKET | Critical | [x] Implemented |
| OPEN_SSH | High | [x] Implemented |
| OPEN_RDP | High | [x] Implemented |
| OPEN_ALL_PORTS | Critical | [x] Implemented |
| NO_MFA | Medium | [x] Implemented |
| WEAK_IAM_POLICY | Medium | [x] Implemented |
| UNENCRYPTED_EBS | High | [x] Implemented |
| HTTP_LISTENER | Medium | [x] Implemented |

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

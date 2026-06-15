# SECURITY_AND_PII.md
## Enterprise Security Guardrail Auditor
## Security Controls & PII Handling Specification

---

## 1. SECURITY RULES — FULL SPECIFICATION

The rules engine must implement ALL rules below.
Each rule must return a Finding with: rule_id, severity, points, resource_name, description.

### Terraform (.tf) Rules

#### CRITICAL (40 points each)

**PUBLIC_S3_BUCKET**
```
Trigger: aws_s3_bucket resource where acl = "public-read" OR "public-read-write"
         OR aws_s3_bucket_acl where acl = "public-read" OR "public-read-write"
         OR aws_s3_bucket_public_access_block where block_public_acls = false
Description: "S3 bucket {resource_name} has public read/write access enabled.
             This exposes all bucket contents to the internet."
Remediation: Set acl = "private" and enable S3 Block Public Access settings.
```

**OPEN_ALL_PORTS**
```
Trigger: aws_security_group or aws_security_group_rule where
         from_port = 0 AND to_port = 0 AND cidr_blocks contains "0.0.0.0/0"
         OR from_port = -1 AND to_port = -1
Description: "Security group {resource_name} allows ALL traffic from the internet (0.0.0.0/0).
             This exposes all services to potential attackers."
Remediation: Restrict ingress to specific ports and known CIDR ranges only.
```

#### HIGH (25 points each)

**OPEN_SSH**
```
Trigger: aws_security_group or aws_security_group_rule where
         from_port <= 22 AND to_port >= 22 AND cidr_blocks contains "0.0.0.0/0"
Description: "Security group {resource_name} exposes SSH (port 22) to the internet.
             This enables brute-force attacks on EC2 instances."
Remediation: Restrict SSH access to known IP ranges or use AWS Systems Manager Session Manager.
```

**OPEN_RDP**
```
Trigger: aws_security_group or aws_security_group_rule where
         from_port <= 3389 AND to_port >= 3389 AND cidr_blocks contains "0.0.0.0/0"
Description: "Security group {resource_name} exposes RDP (port 3389) to the internet.
             Windows Remote Desktop is a common ransomware entry point."
Remediation: Restrict RDP to known IP ranges or use a VPN/bastion host.
```

**UNENCRYPTED_EBS**
```
Trigger: aws_ebs_volume where encrypted = false OR encrypted not set
         OR aws_instance with ebs_block_device where encrypted = false
Description: "EBS volume in {resource_name} has encryption disabled.
             Unencrypted volumes expose data if physical media is compromised."
Remediation: Set encrypted = true. Enable EBS encryption by default in AWS account settings.
```

**UNENCRYPTED_RDS**
```
Trigger: aws_db_instance where storage_encrypted = false OR storage_encrypted not set
Description: "RDS instance {resource_name} has storage encryption disabled.
             Database files are stored unencrypted on disk."
Remediation: Set storage_encrypted = true. Note: requires instance recreation.
```

**HARDCODED_SECRET**
```
Trigger: ANY resource where a value matches patterns:
         - password = "..." (non-empty string literal, not a variable reference)
         - secret = "..." (non-empty string literal)
         - api_key = "..." (non-empty string literal)
         - access_key = "..." (non-empty string literal)
         NOTE: Skip if value starts with var. or data. or local.
Description: "Resource {resource_name} contains a hardcoded secret value in {attribute}.
             Secrets in source code are exposed in version control history."
Remediation: Use AWS Secrets Manager, SSM Parameter Store, or Terraform variables.
```

#### MEDIUM (20 points each)

**NO_MFA**
```
Trigger: aws_iam_user where force_destroy = true AND no associated
         aws_iam_user_login_profile with password_reset_required
         OR aws_iam_user_login_profile exists without mfa enforcement policy
Description: "IAM user {resource_name} does not have MFA enforcement configured.
             Accounts without MFA are vulnerable to credential theft."
Remediation: Attach an IAM policy that requires MFA for all API calls.
```

**WEAK_IAM_POLICY**
```
Trigger: aws_iam_policy or aws_iam_role_policy where policy document contains
         "Action": "*" OR "Action": ["*"]
         AND "Resource": "*" OR "Resource": ["*"]
Description: "IAM policy {resource_name} grants wildcard (*) permissions on all resources.
             This violates the principle of least privilege."
Remediation: Replace wildcard actions with specific required permissions only.
```

**HTTP_LISTENER**
```
Trigger: aws_lb_listener or aws_alb_listener where protocol = "HTTP"
         AND port != 80 (port 80 HTTP->HTTPS redirect is acceptable)
         OR aws_lb_listener where protocol = "HTTP" with no redirect action
Description: "Load balancer listener {resource_name} serves traffic over unencrypted HTTP.
             User data and session tokens are transmitted in plaintext."
Remediation: Change protocol to HTTPS and attach an ACM certificate.
```

**UNRESTRICTED_OUTBOUND**
```
Trigger: aws_security_group where egress contains cidr_blocks "0.0.0.0/0"
         without any ingress restrictions (fully open group)
Description: "Security group {resource_name} allows unrestricted outbound traffic.
             Compromised instances can exfiltrate data to any destination."
Remediation: Restrict egress to required destinations and ports only.
```

---

### CloudFormation (.yaml/.json) Rules

Apply equivalent rules to CloudFormation Resources:

| Terraform resource | CloudFormation equivalent |
|---|---|
| aws_s3_bucket | AWS::S3::Bucket |
| aws_security_group | AWS::EC2::SecurityGroup |
| aws_iam_user | AWS::IAM::User |
| aws_iam_policy | AWS::IAM::Policy / ManagedPolicy |
| aws_ebs_volume | AWS::EC2::Volume |
| aws_db_instance | AWS::RDS::DBInstance |
| aws_lb_listener | AWS::ElasticLoadBalancingV2::Listener |

---

## 2. PII HANDLING — FULL SPECIFICATION

The application processes infrastructure config files that MAY contain sensitive data.
These controls MUST be implemented:

### 2.1 Input Handling

**File type whitelist** — reject everything except:
```python
ALLOWED_EXTENSIONS = {".tf", ".yaml", ".yml", ".json"}
ALLOWED_MIME_TYPES = {"text/plain", "application/x-yaml", "application/json"}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
```

**Filename sanitisation** — before saving temp file:
```python
import re
safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', original_filename)
safe_filename = safe_filename[:255]  # max filename length
```

**Temp file handling** — always use try/finally:
```python
import tempfile, os
try:
    with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as tmp:
        tmp.write(file_content)
        tmp_path = tmp.name
    # process file
finally:
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)  # always delete temp file
```

### 2.2 What NOT to Store in Database

The ScanResult and Finding models must NEVER store:
- Raw file contents
- Actual secret values found (log rule_id + resource_name only, not the value)
- Usernames, passwords, API keys from scanned files
- IP addresses of the scanning client
- File paths beyond the original filename

For HARDCODED_SECRET rule — store only:
```
finding.description = "Hardcoded secret detected in resource {name}, attribute {attr}. Value redacted."
# NEVER store: finding.description = "Password found: 'mysecretpassword123'"
```

### 2.3 Logging Rules

Use Python logging module. NEVER log:
```python
# BAD — never do this
logger.info(f"File content: {file_content}")
logger.debug(f"Secret value found: {secret_value}")
logger.info(f"User uploaded: {original_filename} from IP {client_ip}")

# GOOD — do this
logger.info(f"Scan started: {safe_filename}, size: {file_size_bytes} bytes")
logger.info(f"Scan complete: {scan_id}, findings: {finding_count}, score: {risk_score}")
logger.warning(f"HARDCODED_SECRET detected in resource: {resource_name}")
```

### 2.4 API Response Sanitisation

POST /scan response must NEVER include:
- Raw file content
- Actual secret values
- Internal file paths (use scan_id references only)
- Stack traces (catch all exceptions and return clean error messages)

```python
# BAD
return {"error": str(exception)}  # may expose internal paths

# GOOD
logger.error(f"Scan failed: {exception}")
raise HTTPException(status_code=500, detail="Scan processing failed. Check logs.")
```

### 2.5 Security Headers

Add these headers to ALL FastAPI responses:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# In app/main.py
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

### 2.6 Input Validation

Validate all inputs with Pydantic before processing:
```python
class ScanRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    # file validated at FastAPI layer via UploadFile

class ScanResponse(BaseModel):
    scan_id: int
    filename: str  # sanitised filename only
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["Low", "Medium", "High", "Critical", "Clean"]
    total_findings: int = Field(ge=0)
    findings: list[FindingResponse]
```

---

## 3. RATE LIMITING

Add basic rate limiting to /scan endpoint:
```python
# Simple in-memory rate limiting
# Max 10 scans per minute per client (for demo — use slowapi library)
pip install slowapi

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.post("/scan")
@limiter.limit("10/minute")
async def scan_file(request: Request, file: UploadFile = File(...)):
    ...
```

---

## 4. PROMPT FOR SECURITY IMPLEMENTATION

Use this prompt in Stage 5 after the basic FastAPI layer is working:

```
Security hardening pass — implement all controls from SECURITY_AND_PII.md:

1. Add filename sanitisation to POST /scan before saving temp file
2. Add file type and size validation (max 10MB, .tf/.yaml/.json only)
3. Ensure temp file is always deleted in try/finally block
4. Add security headers middleware to app/main.py
5. Ensure HARDCODED_SECRET rule redacts the actual value in findings
6. Add slowapi rate limiting (10/minute) on POST /scan
7. Ensure no raw file content is ever stored in SQLite
8. Add input validation with Pydantic for all response models
9. Ensure all logging follows the PII rules — no secret values logged

Update SECURITY_AND_PII.md status checkboxes when each control is implemented.
Update prompts.md. Report elapsed time.
```

---

## 5. SECURITY IMPLEMENTATION STATUS

> AI updates these checkboxes as controls are implemented

### Scanner rules
- [x] PUBLIC_S3_BUCKET (Critical)
- [x] OPEN_ALL_PORTS (Critical)
- [x] OPEN_SSH (High)
- [x] OPEN_RDP (High)
- [x] UNENCRYPTED_EBS (High)
- [x] UNENCRYPTED_RDS (High) — added in security pass
- [x] HARDCODED_SECRET (High) — with value redaction; actual value never stored or logged
- [x] NO_MFA (Medium)
- [x] WEAK_IAM_POLICY (Medium)
- [x] HTTP_LISTENER (Medium)
- [x] UNRESTRICTED_OUTBOUND (Medium) — added in security pass

### PII controls
- [x] File type whitelist — ALLOWED_EXTENSIONS = {".tf", ".yaml", ".yml", ".json"}
- [x] Filename sanitisation — re.sub(r'[^a-zA-Z0-9._-]', '_', name)[:255]
- [x] File size limit (10MB) — returns HTTP 413 if exceeded
- [x] Temp file always deleted — try/finally with os.unlink()
- [x] Secret values never stored in DB — description says "Value redacted"
- [x] Secret values never logged — logger.warning logs attribute name only, not value
- [x] Security headers middleware — X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy
- [ ] Pydantic response models — not yet implemented (returning raw dicts; functional but untyped)
- [x] Rate limiting on /scan — slowapi 10/minute per client IP
- [x] Clean error messages — all exceptions caught; no stack traces in API responses

---

*This file is maintained by the AI agent and Mayank as architect.*
*Last updated: 2026-06-15 (Turn 4 — security hardening pass)*

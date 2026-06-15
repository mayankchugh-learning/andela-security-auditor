import logging
import os
import re
import tempfile

from fastapi import APIRouter, Request, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.models import Scan, Finding
from app.scanner.hcl_parser import parse_terraform
from app.scanner.cf_parser import parse_cloudformation
from app.rules.engine import apply_rules
from app.scoring.risk_score import calculate_risk_score

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".tf", ".yaml", ".yml", ".json"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

router = APIRouter()


def _sanitise_filename(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    return safe[:255]


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/scan")
@limiter.limit("10/minute")
async def scan_file(
    request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)
):
    original_name = file.filename or "upload"
    safe_name = _sanitise_filename(original_name)

    ext = os.path.splitext(safe_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Only .tf, .yaml, .yml, and .json files are supported.",
        )

    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB limit.")

    logger.info("Scan started: %s, size: %d bytes", safe_name, len(content_bytes))

    content = content_bytes.decode("utf-8")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(content_bytes)
            tmp_path = tmp.name

        if ext == ".tf":
            file_type = "tf"
            try:
                resources = parse_terraform(content)
            except Exception:
                logger.exception("HCL parse error for %s", safe_name)
                raise HTTPException(
                    status_code=422, detail="HCL parse error. Check file syntax."
                )
        else:
            file_type = "yaml"
            try:
                resources = parse_cloudformation(content)
            except Exception:
                logger.exception("YAML parse error for %s", safe_name)
                raise HTTPException(
                    status_code=422, detail="YAML parse error. Check file syntax."
                )

        findings = apply_rules(resources)
        score, level = calculate_risk_score(findings)

        scan = Scan(
            filename=safe_name,
            file_type=file_type,
            risk_score=score,
            risk_level=level,
            total_findings=len(findings),
        )
        db.add(scan)
        db.flush()

        for f in findings:
            db.add(Finding(scan_id=scan.id, **f))

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan complete: scan_id=%d, findings=%d, score=%d",
            scan.id,
            len(findings),
            score,
        )

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return {
        "scan_id": scan.id,
        "filename": safe_name,
        "file_type": file_type,
        "risk_score": score,
        "risk_level": level,
        "total_findings": len(findings),
        "findings": findings,
    }


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.scanned_at.desc()).all()
    return [
        {
            "scan_id": s.id,
            "filename": s.filename,
            "file_type": s.file_type,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "total_findings": s.total_findings,
            "scanned_at": s.scanned_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id,
        "filename": scan.filename,
        "file_type": scan.file_type,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "total_findings": scan.total_findings,
        "scanned_at": scan.scanned_at.isoformat(),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "points": f.points,
                "description": f.description,
                "resource": f.resource,
            }
            for f in scan.findings
        ],
    }

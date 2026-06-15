from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import Scan, Finding
from app.scanner.hcl_parser import parse_terraform
from app.scanner.cf_parser import parse_cloudformation
from app.rules.engine import apply_rules
from app.scoring.risk_score import calculate_risk_score

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/scan")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = file.filename or ""
    content = (await file.read()).decode("utf-8")

    if filename.endswith(".tf"):
        file_type = "tf"
        try:
            resources = parse_terraform(content)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"HCL parse error: {e}")
    elif filename.endswith((".yaml", ".yml")):
        file_type = "yaml"
        try:
            resources = parse_cloudformation(content)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"YAML parse error: {e}")
    else:
        raise HTTPException(status_code=400, detail="Only .tf and .yaml/.yml files are supported.")

    findings = apply_rules(resources)
    score, level = calculate_risk_score(findings)

    scan = Scan(
        filename=filename,
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

    return {
        "scan_id": scan.id,
        "filename": filename,
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

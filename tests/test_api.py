import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

VULNERABLE_TF = """
resource "aws_s3_bucket" "bad" {
  bucket = "bad"
  acl    = "public-read"
}
"""

CLEAN_TF = """
resource "aws_s3_bucket" "good" {
  bucket = "good"
  acl    = "private"
}
"""

CLEAN_CF = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  GoodBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: good-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
"""


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_scan_vulnerable_tf():
    resp = client.post("/scan", files={"file": ("vulnerable.tf", VULNERABLE_TF, "text/plain")})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 0
    assert any(f["rule_id"] == "PUBLIC_S3_BUCKET" for f in data["findings"])


def test_scan_clean_tf():
    resp = client.post("/scan", files={"file": ("clean.tf", CLEAN_TF, "text/plain")})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_findings"] == 0
    assert data["risk_level"] == "Clean"


def test_scan_cloudformation_yaml():
    resp = client.post("/scan", files={"file": ("infra.yaml", CLEAN_CF, "text/plain")})
    assert resp.status_code == 200
    data = resp.json()
    assert data["file_type"] == "yaml"


def test_scan_unsupported_format():
    resp = client.post("/scan", files={"file": ("script.sh", "echo hi", "text/plain")})
    assert resp.status_code == 400


def test_list_scans():
    resp = client.get("/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_get_scan_not_found():
    resp = client.get("/scans/999999")
    assert resp.status_code == 404

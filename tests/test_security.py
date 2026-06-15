"""Tests for security hardening controls."""

from fastapi.testclient import TestClient
from app.main import app
from app.rules.engine import apply_rules

client = TestClient(app)


# --- HARDCODED_SECRET ---


def test_hardcoded_password_flagged():
    resources = [
        {"type": "aws_db_instance", "name": "db", "config": {"password": "s3cr3t!"}}
    ]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "HARDCODED_SECRET" for f in findings)


def test_variable_reference_not_flagged():
    resources = [
        {
            "type": "aws_db_instance",
            "name": "db",
            "config": {"password": "var.db_password"},
        }
    ]
    findings = apply_rules(resources)
    assert not any(f["rule_id"] == "HARDCODED_SECRET" for f in findings)


def test_hardcoded_secret_value_redacted():
    resources = [
        {"type": "aws_db_instance", "name": "db", "config": {"password": "supersecret"}}
    ]
    findings = apply_rules(resources)
    secret_findings = [f for f in findings if f["rule_id"] == "HARDCODED_SECRET"]
    assert secret_findings
    assert "supersecret" not in secret_findings[0]["description"]
    assert "redacted" in secret_findings[0]["description"].lower()


# --- UNENCRYPTED_RDS ---


def test_unencrypted_rds_flagged():
    resources = [
        {
            "type": "aws_db_instance",
            "name": "mydb",
            "config": {"storage_encrypted": False},
        }
    ]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "UNENCRYPTED_RDS" for f in findings)


def test_encrypted_rds_clean():
    resources = [
        {
            "type": "aws_db_instance",
            "name": "mydb",
            "config": {"storage_encrypted": True},
        }
    ]
    findings = apply_rules(resources)
    assert not any(f["rule_id"] == "UNENCRYPTED_RDS" for f in findings)


# --- UNRESTRICTED_OUTBOUND ---


def test_unrestricted_outbound_flagged():
    resources = [
        {
            "type": "aws_security_group",
            "name": "sg",
            "config": {
                "egress": [
                    {
                        "from_port": 0,
                        "to_port": 0,
                        "protocol": "-1",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
        }
    ]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "UNRESTRICTED_OUTBOUND" for f in findings)


# --- API security controls ---


def test_filename_sanitisation():
    tf = 'resource "aws_s3_bucket" "b" { acl = "private" }'
    resp = client.post(
        "/scan", files={"file": ("../../../etc/passwd.tf", tf.encode(), "text/plain")}
    )
    assert resp.status_code == 200
    assert "../" not in resp.json()["filename"]


def test_oversized_file_rejected():
    big = b"x" * (10 * 1024 * 1024 + 1)
    resp = client.post("/scan", files={"file": ("big.tf", big, "text/plain")})
    assert resp.status_code == 413


def test_unsupported_extension_rejected():
    resp = client.post("/scan", files={"file": ("malware.exe", b"MZ", "text/plain")})
    assert resp.status_code == 400


def test_security_headers_present():
    resp = client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("x-xss-protection") == "1; mode=block"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

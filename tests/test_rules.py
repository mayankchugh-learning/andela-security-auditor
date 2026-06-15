from app.rules.engine import apply_rules
from app.scoring.risk_score import calculate_risk_score


def _res(rtype, rname, cfg):
    return {"type": rtype, "name": rname, "config": cfg}


def test_public_s3_bucket_flagged():
    resources = [_res("aws_s3_bucket", "bad_bucket", {"acl": "public-read"})]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "PUBLIC_S3_BUCKET" for f in findings)


def test_private_s3_bucket_clean():
    resources = [_res("aws_s3_bucket", "good_bucket", {"acl": "private"})]
    findings = apply_rules(resources)
    assert not any(f["rule_id"] == "PUBLIC_S3_BUCKET" for f in findings)


def test_open_ssh_flagged():
    resources = [_res("aws_security_group", "bad_sg", {
        "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
    })]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "OPEN_SSH" for f in findings)


def test_open_rdp_flagged():
    resources = [_res("aws_security_group", "bad_sg", {
        "ingress": [{"from_port": 3389, "to_port": 3389, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
    })]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "OPEN_RDP" for f in findings)


def test_open_all_ports_flagged():
    resources = [_res("aws_security_group", "wide_sg", {
        "ingress": [{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]
    })]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "OPEN_ALL_PORTS" for f in findings)


def test_unencrypted_ebs_flagged():
    resources = [_res("aws_ebs_volume", "bad_vol", {"encrypted": False})]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "UNENCRYPTED_EBS" for f in findings)


def test_http_listener_flagged():
    resources = [_res("aws_lb_listener", "bad_lb", {"protocol": "HTTP"})]
    findings = apply_rules(resources)
    assert any(f["rule_id"] == "HTTP_LISTENER" for f in findings)


def test_risk_score_capped_at_100():
    findings = [{"points": 40}, {"points": 40}, {"points": 40}]
    score, level = calculate_risk_score(findings)
    assert score == 100
    assert level == "Critical Risk"


def test_risk_score_clean():
    score, level = calculate_risk_score([])
    assert score == 0
    assert level == "Clean"


def test_risk_score_levels():
    assert calculate_risk_score([{"points": 20}])[1] == "Low Risk"
    assert calculate_risk_score([{"points": 30}])[1] == "Medium Risk"
    assert calculate_risk_score([{"points": 60}])[1] == "High Risk"
    assert calculate_risk_score([{"points": 80}])[1] == "Critical Risk"

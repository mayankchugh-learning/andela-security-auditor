from app.rules.definitions import RULES, Rule


def _check_open_port(ingress: dict, port: int) -> bool:
    """Return True if the given port is open to 0.0.0.0/0 or ::/0."""
    cidr_blocks = ingress.get("cidr_blocks", [])
    ipv6_blocks = ingress.get("ipv6_cidr_blocks", [])
    all_cidrs = list(cidr_blocks) + list(ipv6_blocks)
    open_cidrs = {"0.0.0.0/0", "::/0"}
    if not any(c in open_cidrs for c in all_cidrs):
        return False
    from_port = ingress.get("from_port", -1)
    to_port = ingress.get("to_port", -1)
    protocol = str(ingress.get("protocol", "")).lower()
    if protocol in ("-1", "all"):
        return True
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def apply_rules(resources: list[dict]) -> list[dict]:
    """Apply all security rules to a flat list of parsed resources.

    Each resource dict must have keys: type, name, config.
    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    for res in resources:
        rtype = res.get("type", "")
        rname = res.get("name", "")
        cfg = res.get("config", {})

        # PUBLIC_S3_BUCKET
        if rtype == "aws_s3_bucket":
            acl = cfg.get("acl", "")
            if acl in ("public-read", "public-read-write", "public"):
                findings.append(_finding("PUBLIC_S3_BUCKET", rname))

        # Security group rules
        if rtype == "aws_security_group":
            ingress_list = cfg.get("ingress", [])
            if not isinstance(ingress_list, list):
                ingress_list = [ingress_list]
            for ingress in ingress_list:
                if not isinstance(ingress, dict):
                    continue
                protocol = str(ingress.get("protocol", "")).lower()
                # OPEN_ALL_PORTS
                if protocol in ("-1", "all"):
                    cidr_blocks = ingress.get("cidr_blocks", [])
                    ipv6_blocks = ingress.get("ipv6_cidr_blocks", [])
                    if any(c in {"0.0.0.0/0", "::/0"} for c in list(cidr_blocks) + list(ipv6_blocks)):
                        findings.append(_finding("OPEN_ALL_PORTS", rname))
                        continue
                if _check_open_port(ingress, 22):
                    findings.append(_finding("OPEN_SSH", rname))
                if _check_open_port(ingress, 3389):
                    findings.append(_finding("OPEN_RDP", rname))

        # NO_MFA
        if rtype == "aws_iam_user":
            # Absence of mfa_configuration or force_destroy=true flags risk
            login_profile = cfg.get("login_profile", {}) or {}
            password_reset = login_profile.get("password_reset_required") if isinstance(login_profile, dict) else None
            # We flag if there's a login_profile but no explicit MFA device policy
            # (simplified: flag if login_profile present without mfa block)
            if cfg.get("login_profile") is not None:
                findings.append(_finding("NO_MFA", rname))

        # WEAK_IAM_POLICY
        if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            policy_doc = cfg.get("policy", "")
            if isinstance(policy_doc, str) and '"Action": "*"' in policy_doc:
                findings.append(_finding("WEAK_IAM_POLICY", rname))
            # Also check parsed policy document
            policy_doc_parsed = cfg.get("policy_document", {})
            if isinstance(policy_doc_parsed, dict):
                for stmt in policy_doc_parsed.get("statement", []):
                    actions = stmt.get("actions", [])
                    if "*" in actions:
                        findings.append(_finding("WEAK_IAM_POLICY", rname))

        # UNENCRYPTED_EBS
        if rtype == "aws_ebs_volume":
            encrypted = cfg.get("encrypted", False)
            if not encrypted:
                findings.append(_finding("UNENCRYPTED_EBS", rname))

        # HTTP_LISTENER
        if rtype in ("aws_lb_listener", "aws_alb_listener"):
            protocol = str(cfg.get("protocol", "")).upper()
            if protocol == "HTTP":
                findings.append(_finding("HTTP_LISTENER", rname))

        # --- CloudFormation resource types ---
        if rtype == "AWS::S3::Bucket":
            props = cfg
            access_control = props.get("AccessControl", "")
            public_config = props.get("PublicAccessBlockConfiguration", {})
            block_public = public_config.get("BlockPublicAcls", True) if public_config else False
            if access_control in ("PublicRead", "PublicReadWrite") or not block_public:
                findings.append(_finding("PUBLIC_S3_BUCKET", rname))

        if rtype == "AWS::EC2::SecurityGroup":
            for rule in cfg.get("SecurityGroupIngress", []):
                proto = str(rule.get("IpProtocol", "")).lower()
                cidr = rule.get("CidrIp", "")
                cidr6 = rule.get("CidrIpv6", "")
                open_cidr = cidr in ("0.0.0.0/0",) or cidr6 in ("::/0",)
                if proto in ("-1",) and open_cidr:
                    findings.append(_finding("OPEN_ALL_PORTS", rname))
                    continue
                from_port = rule.get("FromPort", -1)
                to_port = rule.get("ToPort", -1)
                try:
                    if open_cidr and int(from_port) <= 22 <= int(to_port):
                        findings.append(_finding("OPEN_SSH", rname))
                    if open_cidr and int(from_port) <= 3389 <= int(to_port):
                        findings.append(_finding("OPEN_RDP", rname))
                except (TypeError, ValueError):
                    pass

        if rtype == "AWS::EBS::Volume":
            if not cfg.get("Encrypted", False):
                findings.append(_finding("UNENCRYPTED_EBS", rname))

        if rtype == "AWS::ElasticLoadBalancingV2::Listener":
            if str(cfg.get("Protocol", "")).upper() == "HTTP":
                findings.append(_finding("HTTP_LISTENER", rname))

    return findings


def _finding(rule_id: str, resource: str) -> dict:
    rule: Rule = RULES[rule_id]
    return {
        "rule_id": rule.id,
        "severity": rule.severity,
        "points": rule.points,
        "description": rule.description,
        "resource": resource,
    }

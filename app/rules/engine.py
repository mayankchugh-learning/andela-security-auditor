import logging

from app.rules.definitions import RULES, Rule

logger = logging.getLogger(__name__)

# Attributes to scan for hardcoded secrets
_SECRET_ATTRS = {"password", "secret", "api_key", "access_key", "secret_key", "token"}
# Variable/data reference prefixes that are NOT hardcoded
_SAFE_PREFIXES = ("var.", "data.", "local.", "${")


def _check_open_port(ingress: dict, port: int) -> bool:
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


def _scan_for_secrets(cfg: dict, resource_name: str) -> list[dict]:
    """Return HARDCODED_SECRET findings for any literal secret values in cfg."""
    findings = []
    for key, val in cfg.items():
        if not isinstance(val, str):
            continue
        if key.lower() not in _SECRET_ATTRS:
            continue
        if not val or any(val.startswith(p) for p in _SAFE_PREFIXES):
            continue
        logger.warning(
            "HARDCODED_SECRET detected in resource: %s, attribute: %s",
            resource_name,
            key,
        )
        f = _finding("HARDCODED_SECRET", resource_name)
        # Override description to name the attribute but NEVER include the value
        f["description"] = (
            f"Resource {resource_name} contains a hardcoded secret in attribute '{key}'. "
            "Value redacted. Secrets in source code are exposed in version control history."
        )
        findings.append(f)
    return findings


def apply_rules(resources: list[dict]) -> list[dict]:
    findings: list[dict] = []

    for res in resources:
        rtype = res.get("type", "")
        rname = res.get("name", "")
        cfg = res.get("config", {})

        # --- Terraform resource types ---

        if rtype == "aws_s3_bucket":
            acl = cfg.get("acl", "")
            if acl in ("public-read", "public-read-write", "public"):
                findings.append(_finding("PUBLIC_S3_BUCKET", rname))

        if rtype == "aws_s3_bucket_public_access_block":
            if not cfg.get("block_public_acls", True):
                findings.append(_finding("PUBLIC_S3_BUCKET", rname))

        if rtype == "aws_security_group":
            ingress_list = cfg.get("ingress", [])
            if not isinstance(ingress_list, list):
                ingress_list = [ingress_list]
            for ingress in ingress_list:
                if not isinstance(ingress, dict):
                    continue
                protocol = str(ingress.get("protocol", "")).lower()
                cidr_blocks = ingress.get("cidr_blocks", [])
                ipv6_blocks = ingress.get("ipv6_cidr_blocks", [])
                open_to_world = any(
                    c in {"0.0.0.0/0", "::/0"}
                    for c in list(cidr_blocks) + list(ipv6_blocks)
                )
                if protocol in ("-1", "all") and open_to_world:
                    findings.append(_finding("OPEN_ALL_PORTS", rname))
                    continue
                if _check_open_port(ingress, 22):
                    findings.append(_finding("OPEN_SSH", rname))
                if _check_open_port(ingress, 3389):
                    findings.append(_finding("OPEN_RDP", rname))

            # UNRESTRICTED_OUTBOUND — egress to 0.0.0.0/0
            egress_list = cfg.get("egress", [])
            if not isinstance(egress_list, list):
                egress_list = [egress_list]
            for egress in egress_list:
                if not isinstance(egress, dict):
                    continue
                cidr_blocks = egress.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidr_blocks:
                    findings.append(_finding("UNRESTRICTED_OUTBOUND", rname))
                    break

        if rtype == "aws_iam_user":
            if cfg.get("login_profile") is not None:
                findings.append(_finding("NO_MFA", rname))

        if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            policy_doc = cfg.get("policy", "")
            if isinstance(policy_doc, str) and (
                '"Action": "*"' in policy_doc or '"Action":["*"]' in policy_doc
            ):
                findings.append(_finding("WEAK_IAM_POLICY", rname))

        if rtype == "aws_ebs_volume":
            if not cfg.get("encrypted", False):
                findings.append(_finding("UNENCRYPTED_EBS", rname))

        if rtype == "aws_db_instance":
            if not cfg.get("storage_encrypted", False):
                findings.append(_finding("UNENCRYPTED_RDS", rname))

        if rtype in ("aws_lb_listener", "aws_alb_listener"):
            if str(cfg.get("protocol", "")).upper() == "HTTP":
                findings.append(_finding("HTTP_LISTENER", rname))

        # HARDCODED_SECRET — scan all resource types
        findings.extend(_scan_for_secrets(cfg, rname))

        # --- CloudFormation resource types ---

        if rtype == "AWS::S3::Bucket":
            access_control = cfg.get("AccessControl", "")
            public_config = cfg.get("PublicAccessBlockConfiguration", {})
            block_public = (
                public_config.get("BlockPublicAcls", True) if public_config else False
            )
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
            for rule in cfg.get("SecurityGroupEgress", []):
                cidr = rule.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    findings.append(_finding("UNRESTRICTED_OUTBOUND", rname))
                    break

        if rtype == "AWS::EC2::Volume":
            if not cfg.get("Encrypted", False):
                findings.append(_finding("UNENCRYPTED_EBS", rname))

        if rtype == "AWS::RDS::DBInstance":
            if not cfg.get("StorageEncrypted", False):
                findings.append(_finding("UNENCRYPTED_RDS", rname))

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

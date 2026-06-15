from dataclasses import dataclass


@dataclass
class Rule:
    id: str
    severity: str
    points: int
    description: str


RULES: dict[str, Rule] = {
    "PUBLIC_S3_BUCKET": Rule(
        id="PUBLIC_S3_BUCKET",
        severity="Critical",
        points=40,
        description="S3 bucket with public ACL",
    ),
    "OPEN_SSH": Rule(
        id="OPEN_SSH",
        severity="High",
        points=25,
        description="Port 22 open to 0.0.0.0/0",
    ),
    "OPEN_RDP": Rule(
        id="OPEN_RDP",
        severity="High",
        points=25,
        description="Port 3389 open to 0.0.0.0/0",
    ),
    "OPEN_ALL_PORTS": Rule(
        id="OPEN_ALL_PORTS",
        severity="Critical",
        points=40,
        description="All ports open to 0.0.0.0/0",
    ),
    "NO_MFA": Rule(
        id="NO_MFA",
        severity="Medium",
        points=20,
        description="IAM user without MFA enforced",
    ),
    "WEAK_IAM_POLICY": Rule(
        id="WEAK_IAM_POLICY",
        severity="Medium",
        points=20,
        description="IAM policy with wildcard * actions",
    ),
    "UNENCRYPTED_EBS": Rule(
        id="UNENCRYPTED_EBS",
        severity="High",
        points=25,
        description="EBS volume with encryption disabled",
    ),
    "HTTP_LISTENER": Rule(
        id="HTTP_LISTENER",
        severity="Medium",
        points=20,
        description="Load balancer with HTTP (not HTTPS)",
    ),
}

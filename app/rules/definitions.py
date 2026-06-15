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
        description="S3 bucket has public read/write access enabled. This exposes all bucket contents to the internet.",
    ),
    "OPEN_SSH": Rule(
        id="OPEN_SSH",
        severity="High",
        points=25,
        description="Security group exposes SSH (port 22) to the internet. This enables brute-force attacks on EC2 instances.",
    ),
    "OPEN_RDP": Rule(
        id="OPEN_RDP",
        severity="High",
        points=25,
        description="Security group exposes RDP (port 3389) to the internet. Windows Remote Desktop is a common ransomware entry point.",
    ),
    "OPEN_ALL_PORTS": Rule(
        id="OPEN_ALL_PORTS",
        severity="Critical",
        points=40,
        description="Security group allows ALL traffic from the internet (0.0.0.0/0). This exposes all services to potential attackers.",
    ),
    "NO_MFA": Rule(
        id="NO_MFA",
        severity="Medium",
        points=20,
        description="IAM user does not have MFA enforcement configured. Accounts without MFA are vulnerable to credential theft.",
    ),
    "WEAK_IAM_POLICY": Rule(
        id="WEAK_IAM_POLICY",
        severity="Medium",
        points=20,
        description="IAM policy grants wildcard (*) permissions on all resources. This violates the principle of least privilege.",
    ),
    "UNENCRYPTED_EBS": Rule(
        id="UNENCRYPTED_EBS",
        severity="High",
        points=25,
        description="EBS volume has encryption disabled. Unencrypted volumes expose data if physical media is compromised.",
    ),
    "UNENCRYPTED_RDS": Rule(
        id="UNENCRYPTED_RDS",
        severity="High",
        points=25,
        description="RDS instance has storage encryption disabled. Database files are stored unencrypted on disk.",
    ),
    "HTTP_LISTENER": Rule(
        id="HTTP_LISTENER",
        severity="Medium",
        points=20,
        description="Load balancer listener serves traffic over unencrypted HTTP. User data and session tokens are transmitted in plaintext.",
    ),
    "HARDCODED_SECRET": Rule(
        id="HARDCODED_SECRET",
        severity="High",
        points=25,
        description="Resource contains a hardcoded secret value. Secrets in source code are exposed in version control history.",
    ),
    "UNRESTRICTED_OUTBOUND": Rule(
        id="UNRESTRICTED_OUTBOUND",
        severity="Medium",
        points=20,
        description="Security group allows unrestricted outbound traffic. Compromised instances can exfiltrate data to any destination.",
    ),
}

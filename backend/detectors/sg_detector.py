"""
Security group misconfiguration checks — NOT YET IMPLEMENTED (phase 3).

Planned checks:
  - Inbound rules open to 0.0.0.0/0 (or ::/0) on sensitive ports:
    22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL)

Required IAM permissions (read-only, once implemented):
  ec2:DescribeSecurityGroups
"""

from typing import List, Optional

import boto3

from backend.models import Finding

SENSITIVE_PORTS = {22, 3389, 3306, 5432}


def scan_security_groups(session: Optional[boto3.Session] = None) -> List[Finding]:
    raise NotImplementedError("Security group detector is planned for phase 3 of this project.")

"""
IAM misconfiguration checks — NOT YET IMPLEMENTED (phase 2).

Planned checks:
  - Overly permissive inline/managed policies (Action:* + Resource:*)
  - IAM users without MFA enabled
  - Access keys unused for 90+ days

Required IAM permissions (read-only, once implemented):
  iam:ListUsers, iam:ListPolicies, iam:GetPolicyVersion,
  iam:ListMFADevices, iam:ListAccessKeys, iam:GetAccessKeyLastUsed
"""

from typing import List, Optional

import boto3

from backend.models import Finding


def scan_iam(session: Optional[boto3.Session] = None) -> List[Finding]:
    raise NotImplementedError("IAM detector is planned for phase 2 of this project.")

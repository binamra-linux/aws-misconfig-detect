from typing import List

import boto3

from backend import config
from backend.detectors.s3_detector import scan_s3
from backend.models import Finding


def build_session() -> boto3.Session:
    if config.AWS_PROFILE:
        return boto3.Session(profile_name=config.AWS_PROFILE, region_name=config.AWS_REGION)
    return boto3.Session(region_name=config.AWS_REGION)


def run_scan() -> List[Finding]:
    session = build_session()
    findings: List[Finding] = []

    findings.extend(scan_s3(session))
    # Phase 2: findings.extend(scan_iam(session))
    # Phase 3: findings.extend(scan_security_groups(session))

    return findings


if __name__ == "__main__":
    import json

    results = run_scan()
    print(json.dumps([f.to_dict() for f in results], indent=2))

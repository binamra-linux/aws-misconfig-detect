from typing import List

import boto3

from backend import config
from backend.detectors.cloudtrail_detector import scan_cloudtrail, scan_cloudtrail_checks
from backend.detectors.ebs_detector import scan_ebs, scan_ebs_checks
from backend.detectors.iam_detector import scan_iam, scan_iam_checks
from backend.detectors.rds_detector import scan_rds, scan_rds_checks
from backend.detectors.s3_detector import scan_s3, scan_s3_checks
from backend.detectors.sg_detector import scan_security_groups, scan_security_groups_checks
from backend.models import CheckResult, Finding


def build_session() -> boto3.Session:
    if config.AWS_PROFILE:
        return boto3.Session(profile_name=config.AWS_PROFILE, region_name=config.AWS_REGION)
    return boto3.Session(region_name=config.AWS_REGION)


def run_scan() -> List[Finding]:
    session = build_session()
    findings: List[Finding] = []

    findings.extend(scan_s3(session))
    findings.extend(scan_iam(session))
    findings.extend(scan_security_groups(session))
    findings.extend(scan_ebs(session))
    findings.extend(scan_rds(session))
    findings.extend(scan_cloudtrail(session))

    return findings


def run_full_scan() -> List[CheckResult]:
    """Like run_scan(), but includes PASS results too -- every check performed,
    not just failures. Powers the Resources tab and any real pass-rate stats."""
    session = build_session()
    results: List[CheckResult] = []

    results.extend(scan_s3_checks(session))
    results.extend(scan_iam_checks(session))
    results.extend(scan_security_groups_checks(session))
    results.extend(scan_ebs_checks(session))
    results.extend(scan_rds_checks(session))
    results.extend(scan_cloudtrail_checks(session))

    return results


if __name__ == "__main__":
    import json

    results = run_scan()
    print(json.dumps([f.to_dict() for f in results], indent=2))

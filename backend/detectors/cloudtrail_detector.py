"""
Read-only CloudTrail misconfiguration checks (control numbers cite CIS AWS
Foundations Benchmark v1.5.0, same citation convention as iam_detector.py):
  - no multi-region trail is actively logging for the account (CIS 3.1)
  - the active trail doesn't have log file validation enabled (CIS 3.2) --
    only evaluated if an active trail was found, same "only applicable if"
    pattern as iam_detector.py's MFA check

Account-level, not a per-resource loop -- describe_trails() isn't paginated,
so a single call is enough.

Required IAM permissions (read-only):
  cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus
"""

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from backend.models import CheckResult, CheckStatus, Finding, Severity


def _find_active_trail(cloudtrail, trails: List[dict]) -> Optional[dict]:
    """The first multi-region trail that is actively logging, if any."""
    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        try:
            status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
        except ClientError:
            continue
        if status.get("IsLogging"):
            return trail
    return None


def scan_cloudtrail_checks(session: Optional[boto3.Session] = None) -> List[CheckResult]:
    session = session or boto3.Session()
    cloudtrail = session.client("cloudtrail")
    region = cloudtrail.meta.region_name
    results: List[CheckResult] = []

    try:
        trails = cloudtrail.describe_trails().get("trailList", [])
    except ClientError as e:
        return [CheckResult(
            resource_id=region or "unknown",
            resource_type="CloudTrail",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not scan CloudTrail configuration: {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        )]

    active_trail = _find_active_trail(cloudtrail, trails)

    if active_trail:
        results.append(CheckResult(
            resource_id=active_trail["Name"],
            resource_type="CloudTrail",
            check_type="CLOUDTRAIL_ENABLED",
            status=CheckStatus.PASS,
            description=f"CloudTrail trail '{active_trail['Name']}' is multi-region and actively logging.",
            detail={"trail_arn": active_trail.get("TrailARN")},
            region=region,
        ))
    else:
        results.append(CheckResult(
            resource_id="account",
            resource_type="CloudTrail",
            check_type="CLOUDTRAIL_NOT_ENABLED",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            description="No multi-region CloudTrail trail is actively logging for this account.",
            detail={"trail_count": len(trails)},
            region=region,
        ))

    if active_trail:
        if active_trail.get("LogFileValidationEnabled"):
            results.append(CheckResult(
                resource_id=active_trail["Name"],
                resource_type="CloudTrail",
                check_type="CLOUDTRAIL_LOG_VALIDATION_ENABLED",
                status=CheckStatus.PASS,
                description=f"CloudTrail trail '{active_trail['Name']}' has log file validation enabled.",
                region=region,
            ))
        else:
            results.append(CheckResult(
                resource_id=active_trail["Name"],
                resource_type="CloudTrail",
                check_type="CLOUDTRAIL_LOG_VALIDATION_DISABLED",
                status=CheckStatus.FAIL,
                severity=Severity.LOW,
                description=f"CloudTrail trail '{active_trail['Name']}' does not have log file validation enabled.",
                region=region,
            ))

    return results


def scan_cloudtrail(session: Optional[boto3.Session] = None) -> List[Finding]:
    findings: List[Finding] = []
    for result in scan_cloudtrail_checks(session):
        finding = result.to_finding()
        if finding is not None:
            findings.append(finding)
    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_cloudtrail(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))

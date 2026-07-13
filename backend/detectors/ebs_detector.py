"""
Read-only EBS misconfiguration checks:
  - volumes without encryption at rest
  - snapshots (owned by this account) shared publicly with all AWS accounts

Required IAM permissions (read-only):
  ec2:DescribeVolumes, ec2:DescribeSnapshots, ec2:DescribeSnapshotAttribute
"""

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from backend.models import CheckResult, CheckStatus, Finding, Severity


def _check_volume(volume: dict, region: str) -> CheckResult:
    volume_id = volume["VolumeId"]
    if volume.get("Encrypted"):
        return CheckResult(
            resource_id=volume_id,
            resource_type="EBSVolume",
            check_type="EBS_ENCRYPTION",
            status=CheckStatus.PASS,
            description=f"EBS volume '{volume_id}' is encrypted.",
            region=region,
        )
    return CheckResult(
        resource_id=volume_id,
        resource_type="EBSVolume",
        check_type="EBS_NO_ENCRYPTION",
        status=CheckStatus.FAIL,
        severity=Severity.MEDIUM,
        description=f"EBS volume '{volume_id}' is not encrypted.",
        detail={"state": volume.get("State")},
        region=region,
    )


def _check_snapshot(ec2, snapshot: dict, region: str) -> CheckResult:
    snapshot_id = snapshot["SnapshotId"]
    try:
        attr = ec2.describe_snapshot_attribute(SnapshotId=snapshot_id, Attribute="createVolumePermission")
        permissions = attr.get("CreateVolumePermissions", [])
    except ClientError as e:
        return CheckResult(
            resource_id=snapshot_id,
            resource_type="EBSSnapshot",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not check sharing permissions for snapshot '{snapshot_id}': {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        )

    is_public = any(p.get("Group") == "all" for p in permissions)
    if is_public:
        return CheckResult(
            resource_id=snapshot_id,
            resource_type="EBSSnapshot",
            check_type="EBS_SNAPSHOT_PUBLIC",
            status=CheckStatus.FAIL,
            severity=Severity.CRITICAL,
            description=f"EBS snapshot '{snapshot_id}' is shared publicly with all AWS accounts.",
            detail={"volume_id": snapshot.get("VolumeId")},
            region=region,
        )
    return CheckResult(
        resource_id=snapshot_id,
        resource_type="EBSSnapshot",
        check_type="EBS_SNAPSHOT_NOT_PUBLIC",
        status=CheckStatus.PASS,
        description=f"EBS snapshot '{snapshot_id}' is not shared publicly.",
        region=region,
    )


def scan_ebs_checks(session: Optional[boto3.Session] = None) -> List[CheckResult]:
    session = session or boto3.Session()
    ec2 = session.client("ec2")
    region = ec2.meta.region_name
    results: List[CheckResult] = []

    try:
        for page in ec2.get_paginator("describe_volumes").paginate():
            for volume in page.get("Volumes", []):
                results.append(_check_volume(volume, region))
    except ClientError as e:
        results.append(CheckResult(
            resource_id=region or "unknown",
            resource_type="EBSVolume",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not scan EBS volumes in {region}: {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        ))

    try:
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for snapshot in page.get("Snapshots", []):
                results.append(_check_snapshot(ec2, snapshot, region))
    except ClientError as e:
        results.append(CheckResult(
            resource_id=region or "unknown",
            resource_type="EBSSnapshot",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not scan EBS snapshots in {region}: {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        ))

    return results


def scan_ebs(session: Optional[boto3.Session] = None) -> List[Finding]:
    findings: List[Finding] = []
    for result in scan_ebs_checks(session):
        finding = result.to_finding()
        if finding is not None:
            findings.append(finding)
    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_ebs(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))

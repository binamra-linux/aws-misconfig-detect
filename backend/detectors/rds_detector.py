"""
Read-only RDS misconfiguration checks:
  - DB instances that are publicly accessible
  - DB instances without storage encryption
  - manual DB snapshots (owned by this account) shared publicly with all AWS accounts

Required IAM permissions (read-only):
  rds:DescribeDBInstances, rds:DescribeDBSnapshots, rds:DescribeDBSnapshotAttributes
"""

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from backend.models import CheckResult, CheckStatus, Finding, Severity


def _check_instance(instance: dict, region: str) -> List[CheckResult]:
    instance_id = instance["DBInstanceIdentifier"]
    results: List[CheckResult] = []

    if instance.get("PubliclyAccessible"):
        results.append(CheckResult(
            resource_id=instance_id,
            resource_type="RDSInstance",
            check_type="RDS_PUBLICLY_ACCESSIBLE",
            status=CheckStatus.FAIL,
            severity=Severity.CRITICAL,
            description=f"RDS instance '{instance_id}' is publicly accessible.",
            detail={"engine": instance.get("Engine")},
            region=region,
        ))
    else:
        results.append(CheckResult(
            resource_id=instance_id,
            resource_type="RDSInstance",
            check_type="RDS_NOT_PUBLIC",
            status=CheckStatus.PASS,
            description=f"RDS instance '{instance_id}' is not publicly accessible.",
            region=region,
        ))

    if instance.get("StorageEncrypted"):
        results.append(CheckResult(
            resource_id=instance_id,
            resource_type="RDSInstance",
            check_type="RDS_ENCRYPTION",
            status=CheckStatus.PASS,
            description=f"RDS instance '{instance_id}' has storage encryption enabled.",
            region=region,
        ))
    else:
        results.append(CheckResult(
            resource_id=instance_id,
            resource_type="RDSInstance",
            check_type="RDS_NO_ENCRYPTION",
            status=CheckStatus.FAIL,
            severity=Severity.MEDIUM,
            description=f"RDS instance '{instance_id}' does not have storage encryption enabled.",
            detail={"engine": instance.get("Engine")},
            region=region,
        ))

    return results


def _check_snapshot(rds, snapshot: dict, region: str) -> CheckResult:
    snapshot_id = snapshot["DBSnapshotIdentifier"]
    try:
        attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
        attributes = attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
    except ClientError as e:
        return CheckResult(
            resource_id=snapshot_id,
            resource_type="RDSSnapshot",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not check sharing permissions for snapshot '{snapshot_id}': {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        )

    is_public = any(
        a.get("AttributeName") == "restore" and "all" in a.get("AttributeValues", [])
        for a in attributes
    )
    if is_public:
        return CheckResult(
            resource_id=snapshot_id,
            resource_type="RDSSnapshot",
            check_type="RDS_SNAPSHOT_PUBLIC",
            status=CheckStatus.FAIL,
            severity=Severity.CRITICAL,
            description=f"RDS snapshot '{snapshot_id}' is shared publicly with all AWS accounts.",
            detail={"db_instance_identifier": snapshot.get("DBInstanceIdentifier")},
            region=region,
        )
    return CheckResult(
        resource_id=snapshot_id,
        resource_type="RDSSnapshot",
        check_type="RDS_SNAPSHOT_NOT_PUBLIC",
        status=CheckStatus.PASS,
        description=f"RDS snapshot '{snapshot_id}' is not shared publicly.",
        region=region,
    )


def scan_rds_checks(session: Optional[boto3.Session] = None) -> List[CheckResult]:
    session = session or boto3.Session()
    rds = session.client("rds")
    region = rds.meta.region_name
    results: List[CheckResult] = []

    try:
        for page in rds.get_paginator("describe_db_instances").paginate():
            for instance in page.get("DBInstances", []):
                results.extend(_check_instance(instance, region))
    except ClientError as e:
        results.append(CheckResult(
            resource_id=region or "unknown",
            resource_type="RDSInstance",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not scan RDS instances in {region}: {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        ))

    try:
        for page in rds.get_paginator("describe_db_snapshots").paginate(SnapshotType="manual"):
            for snapshot in page.get("DBSnapshots", []):
                results.append(_check_snapshot(rds, snapshot, region))
    except ClientError as e:
        results.append(CheckResult(
            resource_id=region or "unknown",
            resource_type="RDSSnapshot",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not scan RDS snapshots in {region}: {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        ))

    return results


def scan_rds(session: Optional[boto3.Session] = None) -> List[Finding]:
    findings: List[Finding] = []
    for result in scan_rds_checks(session):
        finding = result.to_finding()
        if finding is not None:
            findings.append(finding)
    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_rds(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))

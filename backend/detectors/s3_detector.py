"""
Read-only S3 misconfiguration checks:
  - public read / write access (bucket ACL + bucket policy status)
  - missing default encryption
  - missing versioning

Required IAM permissions (read-only):
  s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketAcl,
  s3:GetBucketPolicyStatus, s3:GetEncryptionConfiguration, s3:GetBucketVersioning
"""

from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from backend.models import Finding, Severity

PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
WRITE_PERMISSIONS = {"WRITE", "WRITE_ACP", "FULL_CONTROL"}


def _bucket_region(s3_client, bucket_name: str) -> str:
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
    except ClientError:
        return "us-east-1"
    # AWS returns None for the default us-east-1 region.
    return location or "us-east-1"


def _check_public_access(client, bucket: str, region: str) -> List[Finding]:
    findings: List[Finding] = []
    detail: Dict = {}
    public_grants = []

    try:
        status = client.get_bucket_policy_status(Bucket=bucket)
        detail["policy_status"] = status["PolicyStatus"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            detail["policy_status_error"] = e.response["Error"]["Code"]

    try:
        acl = client.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI")
            if uri in PUBLIC_GROUP_URIS:
                public_grants.append({"grantee": uri, "permission": grant["Permission"]})
    except ClientError as e:
        detail["acl_error"] = e.response["Error"]["Code"]

    is_public_by_policy = detail.get("policy_status", {}).get("IsPublic", False)
    is_public_by_acl = bool(public_grants)

    if not (is_public_by_policy or is_public_by_acl):
        return findings

    detail["public_grants"] = public_grants
    has_public_write = any(g["permission"] in WRITE_PERMISSIONS for g in public_grants)

    if has_public_write:
        findings.append(Finding(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_PUBLIC_WRITE",
            severity=Severity.CRITICAL,
            description=f"S3 bucket '{bucket}' grants public WRITE access via its ACL.",
            detail=detail,
            region=region,
        ))
    else:
        findings.append(Finding(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_PUBLIC_READ",
            severity=Severity.HIGH,
            description=f"S3 bucket '{bucket}' is publicly accessible (policy and/or ACL grants access to everyone).",
            detail=detail,
            region=region,
        ))
    return findings


def _check_encryption(client, bucket: str, region: str) -> List[Finding]:
    try:
        client.get_bucket_encryption(Bucket=bucket)
        return []
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
            raise
        return [Finding(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_NO_ENCRYPTION",
            severity=Severity.MEDIUM,
            description=f"S3 bucket '{bucket}' has no default server-side encryption configured.",
            detail={"error_code": e.response["Error"]["Code"]},
            region=region,
        )]


def _check_versioning(client, bucket: str, region: str) -> List[Finding]:
    resp = client.get_bucket_versioning(Bucket=bucket)
    status = resp.get("Status")
    if status == "Enabled":
        return []
    return [Finding(
        resource_id=bucket,
        resource_type="S3Bucket",
        check_type="S3_VERSIONING_DISABLED",
        severity=Severity.LOW,
        description=f"S3 bucket '{bucket}' does not have versioning enabled.",
        detail={"versioning_status": status or "Disabled"},
        region=region,
    )]


def scan_s3(session: Optional[boto3.Session] = None) -> List[Finding]:
    session = session or boto3.Session()
    s3 = session.client("s3")
    findings: List[Finding] = []

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        region = _bucket_region(s3, name)
        # Some checks are region-specific (e.g. buckets outside us-east-1
        # reject requests made against the default client's endpoint).
        client = session.client("s3", region_name=region)

        try:
            findings.extend(_check_public_access(client, name, region))
            findings.extend(_check_encryption(client, name, region))
            findings.extend(_check_versioning(client, name, region))
        except ClientError as e:
            findings.append(Finding(
                resource_id=name,
                resource_type="S3Bucket",
                check_type="SCAN_ERROR",
                severity=Severity.LOW,
                description=f"Could not fully scan bucket '{name}': {e.response['Error']['Code']}",
                detail={"error": str(e)},
                region=region,
            ))

    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_s3(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))

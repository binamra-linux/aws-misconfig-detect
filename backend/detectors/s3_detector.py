"""
Read-only S3 misconfiguration checks:
  - account-level Block Public Access not fully enabled
  - public read / write access (bucket ACL + bucket policy status)
  - missing default encryption
  - missing versioning

Required IAM permissions (read-only):
  s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketAcl,
  s3:GetBucketPolicyStatus, s3:GetEncryptionConfiguration, s3:GetBucketVersioning,
  s3:GetAccountPublicAccessBlock, sts:GetCallerIdentity
"""

from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from backend.models import CheckResult, CheckStatus, Finding, Severity

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


def _check_public_access(client, bucket: str, region: str) -> CheckResult:
    detail: Dict = {}
    public_grants = []

    try:
        status = client.get_bucket_policy_status(Bucket=bucket)
        detail["policy_status"] = status["PolicyStatus"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            detail["policy_status_error"] = e.response["Error"]["Code"]
    except (KeyError, TypeError) as e:
        # An unexpected response shape must not abort the whole scan -- record it
        # and fall back to the ACL check below, which is an independent signal.
        detail["policy_status_error"] = f"unexpected response shape: {e}"

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
        return CheckResult(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_PUBLIC_ACCESS",
            status=CheckStatus.PASS,
            description=f"S3 bucket '{bucket}' is not publicly accessible.",
            detail=detail,
            region=region,
        )

    detail["public_grants"] = public_grants
    has_public_write = any(g["permission"] in WRITE_PERMISSIONS for g in public_grants)

    if has_public_write:
        return CheckResult(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_PUBLIC_WRITE",
            status=CheckStatus.FAIL,
            severity=Severity.CRITICAL,
            description=f"S3 bucket '{bucket}' grants public WRITE access via its ACL.",
            detail=detail,
            region=region,
        )

    return CheckResult(
        resource_id=bucket,
        resource_type="S3Bucket",
        check_type="S3_PUBLIC_READ",
        status=CheckStatus.FAIL,
        severity=Severity.HIGH,
        description=f"S3 bucket '{bucket}' is publicly accessible (policy and/or ACL grants access to everyone).",
        detail=detail,
        region=region,
    )


def _check_encryption(client, bucket: str, region: str) -> CheckResult:
    try:
        client.get_bucket_encryption(Bucket=bucket)
        return CheckResult(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_ENCRYPTION",
            status=CheckStatus.PASS,
            description=f"S3 bucket '{bucket}' has default server-side encryption configured.",
            region=region,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
            raise
        return CheckResult(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_NO_ENCRYPTION",
            status=CheckStatus.FAIL,
            severity=Severity.MEDIUM,
            description=f"S3 bucket '{bucket}' has no default server-side encryption configured.",
            detail={"error_code": e.response["Error"]["Code"]},
            region=region,
        )


def _check_versioning(client, bucket: str, region: str) -> CheckResult:
    resp = client.get_bucket_versioning(Bucket=bucket)
    status = resp.get("Status")
    if status == "Enabled":
        return CheckResult(
            resource_id=bucket,
            resource_type="S3Bucket",
            check_type="S3_VERSIONING",
            status=CheckStatus.PASS,
            description=f"S3 bucket '{bucket}' has versioning enabled.",
            detail={"versioning_status": status},
            region=region,
        )
    return CheckResult(
        resource_id=bucket,
        resource_type="S3Bucket",
        check_type="S3_VERSIONING_DISABLED",
        status=CheckStatus.FAIL,
        severity=Severity.LOW,
        description=f"S3 bucket '{bucket}' does not have versioning enabled.",
        detail={"versioning_status": status or "Disabled"},
        region=region,
    )


def _check_bucket(client, bucket: str, region: str) -> List[CheckResult]:
    return [
        _check_public_access(client, bucket, region),
        _check_encryption(client, bucket, region),
        _check_versioning(client, bucket, region),
    ]


# The four account-level Block Public Access switches. All four on is the only
# configuration that actually guarantees no bucket can be made public.
BPA_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def _check_account_public_access_block(session: boto3.Session) -> CheckResult:
    """Account-wide Block Public Access -- the backstop that prevents *any* bucket
    from being exposed, regardless of its individual ACL/policy."""
    account_id = session.client("sts").get_caller_identity()["Account"]
    s3control = session.client("s3control")

    try:
        config_block = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return CheckResult(
            resource_id=account_id,
            resource_type="S3Account",
            check_type="S3_ACCOUNT_BPA_DISABLED",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            description="Account-level S3 Block Public Access is not configured, so any bucket can be made public.",
            detail={"public_access_block": None},
        )

    disabled = [s for s in BPA_SETTINGS if not config_block.get(s)]

    if not disabled:
        return CheckResult(
            resource_id=account_id,
            resource_type="S3Account",
            check_type="S3_ACCOUNT_BPA_DISABLED",
            status=CheckStatus.PASS,
            description="Account-level S3 Block Public Access is fully enabled.",
            detail={"public_access_block": config_block},
        )

    return CheckResult(
        resource_id=account_id,
        resource_type="S3Account",
        check_type="S3_ACCOUNT_BPA_DISABLED",
        status=CheckStatus.FAIL,
        severity=Severity.HIGH,
        description=(
            "Account-level S3 Block Public Access is incomplete: "
            f"{', '.join(disabled)} not enabled."
        ),
        detail={"public_access_block": config_block, "disabled": disabled},
    )


def scan_s3_checks(session: Optional[boto3.Session] = None) -> List[CheckResult]:
    session = session or boto3.Session()
    s3 = session.client("s3")
    results: List[CheckResult] = []

    try:
        results.append(_check_account_public_access_block(session))
    except ClientError as e:
        results.append(CheckResult(
            resource_id="account",
            resource_type="S3Account",
            check_type="SCAN_ERROR",
            status=CheckStatus.FAIL,
            severity=Severity.LOW,
            description=f"Could not check account-level Block Public Access: {e.response['Error']['Code']}",
            detail={"error": str(e)},
        ))

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        region = _bucket_region(s3, name)
        # Some checks are region-specific (e.g. buckets outside us-east-1
        # reject requests made against the default client's endpoint).
        client = session.client("s3", region_name=region)

        try:
            results.extend(_check_bucket(client, name, region))
        except ClientError as e:
            results.append(CheckResult(
                resource_id=name,
                resource_type="S3Bucket",
                check_type="SCAN_ERROR",
                status=CheckStatus.FAIL,
                severity=Severity.LOW,
                description=f"Could not fully scan bucket '{name}': {e.response['Error']['Code']}",
                detail={"error": str(e)},
                region=region,
            ))

    return results


def scan_s3(session: Optional[boto3.Session] = None) -> List[Finding]:
    findings: List[Finding] = []
    for result in scan_s3_checks(session):
        finding = result.to_finding()
        if finding is not None:
            findings.append(finding)
    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_s3(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))

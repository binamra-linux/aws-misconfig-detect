"""
One-click remediation: the ONLY place in this codebase that writes to AWS.

Everything else is strictly read-only, and that guarantee is worth protecting --
so remediation is gated behind config.REMEDIATION_ENABLED (default false) and
each action must be confirmed in the UI, which shows the exact AWS call first.

Each remediation is deliberately a single, well-understood, reversible call. No
action here deletes data: buckets get *blocked*, not emptied; snapshots get
*unshared*, not removed; the security-group fix revokes only the specific
public-CIDR rule that was flagged, leaving every other rule alone.
"""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import boto3

from backend.models import Finding


@dataclass(frozen=True)
class Remediation:
    #  Shown to the user *before* they confirm -- must describe the literal API call.
    description: str
    apply: Callable[[boto3.Session, Finding], str]


def _regional(session: boto3.Session, finding: Finding, service: str):
    """A client pinned to the finding's own region. A security group in eu-west-1
    can't be fixed through a us-east-1 client."""
    return session.client(service, region_name=finding.region) if finding.region else session.client(service)


def _block_s3_public_access(session: boto3.Session, finding: Finding) -> str:
    s3 = _regional(session, finding, "s3")
    s3.put_public_access_block(
        Bucket=finding.resource_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return f"Enabled all four Block Public Access settings on bucket '{finding.resource_id}'."


def _enable_s3_encryption(session: boto3.Session, finding: Finding) -> str:
    s3 = _regional(session, finding, "s3")
    s3.put_bucket_encryption(
        Bucket=finding.resource_id,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    return f"Enabled default AES256 encryption on bucket '{finding.resource_id}'."


def _enable_s3_versioning(session: boto3.Session, finding: Finding) -> str:
    s3 = _regional(session, finding, "s3")
    s3.put_bucket_versioning(
        Bucket=finding.resource_id,
        VersioningConfiguration={"Status": "Enabled"},
    )
    return f"Enabled versioning on bucket '{finding.resource_id}'."


def _revoke_public_ingress(session: boto3.Session, finding: Finding) -> str:
    """Revoke only the public-CIDR rule for the flagged port -- not the whole group."""
    ec2 = _regional(session, finding, "ec2")

    port = finding.detail.get("port")
    protocol = finding.detail.get("protocol", "tcp")
    public_cidrs: List[str] = finding.detail.get("public_cidrs", [])

    if port is None or not public_cidrs:
        raise ValueError("This finding is missing the port/CIDR detail needed to revoke the rule.")

    # -1 means "all protocols", which can't carry port bounds in a revoke call.
    permission: Dict = {"IpProtocol": protocol}
    if protocol != "-1":
        permission["FromPort"] = port
        permission["ToPort"] = port

    ipv4 = [{"CidrIp": c} for c in public_cidrs if ":" not in c]
    ipv6 = [{"CidrIpv6": c} for c in public_cidrs if ":" in c]
    if ipv4:
        permission["IpRanges"] = ipv4
    if ipv6:
        permission["Ipv6Ranges"] = ipv6

    ec2.revoke_security_group_ingress(GroupId=finding.resource_id, IpPermissions=[permission])
    return (
        f"Revoked inbound access to port {port} from {', '.join(public_cidrs)} "
        f"on security group '{finding.resource_id}'."
    )


def _unshare_ebs_snapshot(session: boto3.Session, finding: Finding) -> str:
    ec2 = _regional(session, finding, "ec2")
    ec2.modify_snapshot_attribute(
        SnapshotId=finding.resource_id,
        Attribute="createVolumePermission",
        OperationType="remove",
        GroupNames=["all"],
    )
    return f"Removed public sharing from EBS snapshot '{finding.resource_id}'."


def _unshare_rds_snapshot(session: boto3.Session, finding: Finding) -> str:
    rds = _regional(session, finding, "rds")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier=finding.resource_id,
        AttributeName="restore",
        ValuesToRemove=["all"],
    )
    return f"Removed public sharing from RDS snapshot '{finding.resource_id}'."


def _enable_cloudtrail_log_validation(session: boto3.Session, finding: Finding) -> str:
    cloudtrail = _regional(session, finding, "cloudtrail")
    cloudtrail.update_trail(Name=finding.resource_id, EnableLogFileValidation=True)
    return f"Enabled log file validation on CloudTrail trail '{finding.resource_id}'."


REMEDIATIONS: Dict[str, Remediation] = {
    "S3_PUBLIC_READ": Remediation(
        description="Calls s3:PutPublicAccessBlock to enable all four Block Public Access settings on this bucket.",
        apply=_block_s3_public_access,
    ),
    "S3_PUBLIC_WRITE": Remediation(
        description="Calls s3:PutPublicAccessBlock to enable all four Block Public Access settings on this bucket.",
        apply=_block_s3_public_access,
    ),
    "S3_NO_ENCRYPTION": Remediation(
        description="Calls s3:PutBucketEncryption to set default AES256 server-side encryption on this bucket.",
        apply=_enable_s3_encryption,
    ),
    "S3_VERSIONING_DISABLED": Remediation(
        description="Calls s3:PutBucketVersioning to enable versioning on this bucket.",
        apply=_enable_s3_versioning,
    ),
    "SG_OPEN_SENSITIVE_PORT": Remediation(
        description=(
            "Calls ec2:RevokeSecurityGroupIngress to remove ONLY the public-internet rule "
            "for this port. Other rules in the group are left untouched."
        ),
        apply=_revoke_public_ingress,
    ),
    "EBS_SNAPSHOT_PUBLIC": Remediation(
        description="Calls ec2:ModifySnapshotAttribute to stop sharing this snapshot with all AWS accounts.",
        apply=_unshare_ebs_snapshot,
    ),
    "RDS_SNAPSHOT_PUBLIC": Remediation(
        description="Calls rds:ModifyDBSnapshotAttribute to stop sharing this snapshot with all AWS accounts.",
        apply=_unshare_rds_snapshot,
    ),
    "CLOUDTRAIL_LOG_VALIDATION_DISABLED": Remediation(
        description="Calls cloudtrail:UpdateTrail to enable log file validation on this trail.",
        apply=_enable_cloudtrail_log_validation,
    ),
}


def get_remediation(check_type: str) -> Optional[Remediation]:
    return REMEDIATIONS.get(check_type)

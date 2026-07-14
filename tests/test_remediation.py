"""
Remediation tests.

These assert the fix *actually changes the resource state* in AWS, not merely that
the call didn't raise. This is the only code in the project that writes to AWS, so
"it returned 200" is not sufficient evidence that it worked.
"""

from moto import mock_aws

from tests.conftest import AWS_REGION

from backend.models import Finding, Severity
from backend.remediation import REMEDIATIONS, get_remediation


def _finding(check_type, resource_id, detail=None, region=AWS_REGION):
    return Finding(
        resource_id=resource_id,
        resource_type="T",
        check_type=check_type,
        severity=Severity.HIGH,
        description="d",
        detail=detail or {},
        region=region,
    )


def test_unknown_check_type_has_no_remediation():
    assert get_remediation("SOME_UNFIXABLE_CHECK") is None


def test_every_remediation_documents_the_api_call_it_makes():
    # The UI shows this text in the confirm step. An empty/vague description would
    # mean asking someone to approve an AWS write they can't see.
    for check_type, remediation in REMEDIATIONS.items():
        assert remediation.description.strip(), f"{check_type} has no description"
        assert "Calls " in remediation.description, f"{check_type} doesn't name its API call"


@mock_aws
def test_block_s3_public_access(session):
    s3 = session.client("s3", region_name=AWS_REGION)
    s3.create_bucket(Bucket="public-bucket")

    get_remediation("S3_PUBLIC_READ").apply(session, _finding("S3_PUBLIC_READ", "public-bucket"))

    block = s3.get_public_access_block(Bucket="public-bucket")["PublicAccessBlockConfiguration"]
    assert block == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }


@mock_aws
def test_enable_s3_encryption(session):
    s3 = session.client("s3", region_name=AWS_REGION)
    s3.create_bucket(Bucket="plain-bucket")

    get_remediation("S3_NO_ENCRYPTION").apply(session, _finding("S3_NO_ENCRYPTION", "plain-bucket"))

    rules = s3.get_bucket_encryption(Bucket="plain-bucket")["ServerSideEncryptionConfiguration"]["Rules"]
    assert rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


@mock_aws
def test_enable_s3_versioning(session):
    s3 = session.client("s3", region_name=AWS_REGION)
    s3.create_bucket(Bucket="unversioned")

    get_remediation("S3_VERSIONING_DISABLED").apply(
        session, _finding("S3_VERSIONING_DISABLED", "unversioned")
    )

    assert s3.get_bucket_versioning(Bucket="unversioned")["Status"] == "Enabled"


@mock_aws
def test_revoke_public_ingress_removes_only_the_flagged_rule(session):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    group_id = ec2.create_security_group(GroupName="g", Description="d", VpcId=vpc["VpcId"])["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            # The offending rule...
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            # ...and a legitimate one that must survive.
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ],
    )

    get_remediation("SG_OPEN_SENSITIVE_PORT").apply(
        session,
        _finding(
            "SG_OPEN_SENSITIVE_PORT",
            group_id,
            detail={"port": 22, "protocol": "tcp", "public_cidrs": ["0.0.0.0/0"]},
        ),
    )

    remaining = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]["IpPermissions"]
    ports = {p["FromPort"] for p in remaining}

    # A fix that nuked every rule would "resolve" the finding while breaking prod.
    assert 22 not in ports
    assert 443 in ports


@mock_aws
def test_unshare_ebs_snapshot(session):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    volume_id = ec2.create_volume(AvailabilityZone=f"{AWS_REGION}a", Size=1)["VolumeId"]
    snapshot_id = ec2.create_snapshot(VolumeId=volume_id)["SnapshotId"]
    ec2.modify_snapshot_attribute(
        SnapshotId=snapshot_id,
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )

    get_remediation("EBS_SNAPSHOT_PUBLIC").apply(
        session, _finding("EBS_SNAPSHOT_PUBLIC", snapshot_id)
    )

    permissions = ec2.describe_snapshot_attribute(
        SnapshotId=snapshot_id, Attribute="createVolumePermission"
    )["CreateVolumePermissions"]
    assert not any(p.get("Group") == "all" for p in permissions)


@mock_aws
def test_unshare_rds_snapshot(session):
    rds = session.client("rds", region_name=AWS_REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="correct-horse-battery",
        AllocatedStorage=20,
    )
    rds.create_db_snapshot(DBSnapshotIdentifier="snap", DBInstanceIdentifier="db")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier="snap", AttributeName="restore", ValuesToAdd=["all"]
    )

    get_remediation("RDS_SNAPSHOT_PUBLIC").apply(session, _finding("RDS_SNAPSHOT_PUBLIC", "snap"))

    attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier="snap")[
        "DBSnapshotAttributesResult"
    ]["DBSnapshotAttributes"]
    restore = next(a for a in attrs if a["AttributeName"] == "restore")
    assert "all" not in restore["AttributeValues"]


@mock_aws
def test_enable_cloudtrail_log_validation(session):
    s3 = session.client("s3", region_name=AWS_REGION)
    s3.create_bucket(Bucket="trail-logs")
    cloudtrail = session.client("cloudtrail", region_name=AWS_REGION)
    cloudtrail.create_trail(
        Name="main", S3BucketName="trail-logs", IsMultiRegionTrail=True, EnableLogFileValidation=False
    )

    get_remediation("CLOUDTRAIL_LOG_VALIDATION_DISABLED").apply(
        session, _finding("CLOUDTRAIL_LOG_VALIDATION_DISABLED", "main")
    )

    trail = cloudtrail.describe_trails()["trailList"][0]
    assert trail["LogFileValidationEnabled"] is True


@mock_aws
def test_revoke_ingress_without_required_detail_raises(session):
    remediation = get_remediation("SG_OPEN_SENSITIVE_PORT")

    # A finding missing port/CIDR detail can't be safely acted on -- better to fail
    # loudly than to guess at which rule to revoke.
    try:
        remediation.apply(session, _finding("SG_OPEN_SENSITIVE_PORT", "sg-123", detail={}))
    except ValueError as e:
        assert "missing" in str(e).lower()
    else:
        raise AssertionError("expected a ValueError for a finding with no port/CIDR detail")

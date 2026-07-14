"""
S3 detector tests.

KNOWN COVERAGE GAP: moto does not implement s3:GetBucketPolicyStatus, so the
*policy*-based half of the public-access check can't be exercised here -- only the
ACL-based half. The detector treats them as independent signals (either one can
mark a bucket public), so the ACL path is still a meaningful test; just don't read
these tests as proving policy-based detection works. That path is verified against
a real AWS account instead.
"""

import boto3
import pytest
from moto import mock_aws

from tests.conftest import AWS_REGION, one_check

from backend.detectors.s3_detector import scan_s3_checks
from backend.models import CheckStatus, Severity


def _s3(session):
    return session.client("s3", region_name=AWS_REGION)


@mock_aws
def test_private_encrypted_versioned_bucket_passes(session):
    s3 = _s3(session)
    s3.create_bucket(Bucket="good-bucket")
    s3.put_bucket_encryption(
        Bucket="good-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket="good-bucket", VersioningConfiguration={"Status": "Enabled"})

    results = scan_s3_checks(session)

    assert one_check(results, "S3_PUBLIC_ACCESS").status == CheckStatus.PASS
    assert one_check(results, "S3_ENCRYPTION").status == CheckStatus.PASS
    assert one_check(results, "S3_VERSIONING").status == CheckStatus.PASS


@mock_aws
def test_bucket_without_encryption_or_versioning_fails(session):
    _s3(session).create_bucket(Bucket="bare-bucket")

    results = scan_s3_checks(session)

    no_enc = one_check(results, "S3_NO_ENCRYPTION")
    assert no_enc.status == CheckStatus.FAIL
    assert no_enc.severity == Severity.MEDIUM

    no_ver = one_check(results, "S3_VERSIONING_DISABLED")
    assert no_ver.status == CheckStatus.FAIL
    assert no_ver.severity == Severity.LOW


@mock_aws
def test_public_read_acl_is_detected(session):
    s3 = _s3(session)
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    results = scan_s3_checks(session)

    finding = one_check(results, "S3_PUBLIC_READ")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "public-bucket"


@mock_aws
def test_public_write_acl_is_critical(session):
    s3 = _s3(session)
    s3.create_bucket(Bucket="writable-bucket")

    # NB: the canned ACL "public-read-write" can't be used here. moto only emits a
    # READ grant for it (verified against moto 5.2), where real AWS emits READ *and*
    # WRITE -- so the canned form would silently test the public-read path instead.
    # Granting WRITE explicitly reproduces what AWS actually returns.
    owner = s3.get_bucket_acl(Bucket="writable-bucket")["Owner"]
    s3.put_bucket_acl(
        Bucket="writable-bucket",
        AccessControlPolicy={
            "Owner": owner,
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "WRITE",
                }
            ],
        },
    )

    results = scan_s3_checks(session)

    finding = one_check(results, "S3_PUBLIC_WRITE")
    assert finding.status == CheckStatus.FAIL
    # Public *write* is worse than public read -- anyone can plant objects.
    assert finding.severity == Severity.CRITICAL


@mock_aws
def test_account_block_public_access_missing_is_flagged(session):
    _s3(session).create_bucket(Bucket="any-bucket")

    results = scan_s3_checks(session)

    bpa = one_check(results, "S3_ACCOUNT_BPA_DISABLED")
    assert bpa.status == CheckStatus.FAIL
    assert bpa.severity == Severity.HIGH


@mock_aws
def test_account_block_public_access_enabled_passes(session):
    _s3(session).create_bucket(Bucket="any-bucket")
    account_id = session.client("sts", region_name=AWS_REGION).get_caller_identity()["Account"]
    session.client("s3control", region_name=AWS_REGION).put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    results = scan_s3_checks(session)

    assert one_check(results, "S3_ACCOUNT_BPA_DISABLED").status == CheckStatus.PASS


@mock_aws
def test_partial_block_public_access_still_fails(session):
    _s3(session).create_bucket(Bucket="any-bucket")
    account_id = session.client("sts", region_name=AWS_REGION).get_caller_identity()["Account"]
    session.client("s3control", region_name=AWS_REGION).put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,  # a gap is still a gap
            "RestrictPublicBuckets": False,
        },
    )

    results = scan_s3_checks(session)

    bpa = one_check(results, "S3_ACCOUNT_BPA_DISABLED")
    assert bpa.status == CheckStatus.FAIL
    assert set(bpa.detail["disabled"]) == {"BlockPublicPolicy", "RestrictPublicBuckets"}


@mock_aws
def test_no_buckets_yields_only_account_check(session):
    results = scan_s3_checks(session)

    # An empty account still gets the account-level BPA check -- but nothing else.
    assert {r.check_type for r in results} == {"S3_ACCOUNT_BPA_DISABLED"}

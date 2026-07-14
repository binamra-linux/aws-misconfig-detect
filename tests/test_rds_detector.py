from moto import mock_aws

from tests.conftest import AWS_REGION, one_check

from backend.detectors.rds_detector import scan_rds_checks
from backend.models import CheckStatus, Severity


def _db(session, identifier, public, encrypted):
    rds = session.client("rds", region_name=AWS_REGION)
    rds.create_db_instance(
        DBInstanceIdentifier=identifier,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="correct-horse-battery",
        PubliclyAccessible=public,
        StorageEncrypted=encrypted,
        AllocatedStorage=20,
    )
    return rds


@mock_aws
def test_private_encrypted_instance_passes(session):
    _db(session, "good-db", public=False, encrypted=True)

    results = scan_rds_checks(session)

    assert one_check(results, "RDS_NOT_PUBLIC").status == CheckStatus.PASS
    assert one_check(results, "RDS_ENCRYPTION").status == CheckStatus.PASS


@mock_aws
def test_public_instance_is_critical(session):
    _db(session, "exposed-db", public=True, encrypted=True)

    results = scan_rds_checks(session)

    finding = one_check(results, "RDS_PUBLICLY_ACCESSIBLE")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.CRITICAL
    assert finding.resource_id == "exposed-db"


@mock_aws
def test_unencrypted_instance_fails(session):
    _db(session, "plain-db", public=False, encrypted=False)

    results = scan_rds_checks(session)

    finding = one_check(results, "RDS_NO_ENCRYPTION")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.MEDIUM


@mock_aws
def test_private_snapshot_passes(session):
    rds = _db(session, "snap-db", public=False, encrypted=True)
    rds.create_db_snapshot(DBSnapshotIdentifier="snap-1", DBInstanceIdentifier="snap-db")

    results = scan_rds_checks(session)

    assert one_check(results, "RDS_SNAPSHOT_NOT_PUBLIC").status == CheckStatus.PASS


@mock_aws
def test_publicly_shared_snapshot_is_critical(session):
    rds = _db(session, "snap-db", public=False, encrypted=True)
    rds.create_db_snapshot(DBSnapshotIdentifier="snap-1", DBInstanceIdentifier="snap-db")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier="snap-1",
        AttributeName="restore",
        ValuesToAdd=["all"],
    )

    results = scan_rds_checks(session)

    finding = one_check(results, "RDS_SNAPSHOT_PUBLIC")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.CRITICAL
    assert finding.resource_id == "snap-1"


@mock_aws
def test_empty_account_yields_no_checks(session):
    assert scan_rds_checks(session) == []

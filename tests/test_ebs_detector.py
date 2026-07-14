"""
EBS detector tests.

KNOWN moto LIMITATION: moto ignores the OwnerIds filter on describe_snapshots --
it returns its entire seeded AMI catalogue (~1177 snapshots owned by *other*
accounts) even for OwnerIds=["self"]. Real AWS filters these out correctly, which
is why the detector passes OwnerIds=["self"] and why that's the right call.

Consequence for these tests: snapshot assertions must be scoped to the specific
snapshot the test created, and we can't assert on totals or emptiness of the
snapshot results. Volume results are unaffected -- moto seeds no volumes.
"""

from moto import mock_aws

from tests.conftest import AWS_REGION, by_check, one_check

from backend.detectors.ebs_detector import scan_ebs_checks
from backend.models import CheckStatus, Severity


def _volume(session, encrypted):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    return ec2.create_volume(AvailabilityZone=f"{AWS_REGION}a", Size=1, Encrypted=encrypted)["VolumeId"]


def _for_resource(results, check_type, resource_id):
    matches = [r for r in by_check(results, check_type) if r.resource_id == resource_id]
    assert len(matches) == 1, f"expected one {check_type} for {resource_id}, got {len(matches)}"
    return matches[0]


@mock_aws
def test_encrypted_volume_passes(session):
    _volume(session, encrypted=True)

    results = scan_ebs_checks(session)

    assert one_check(results, "EBS_ENCRYPTION").status == CheckStatus.PASS


@mock_aws
def test_unencrypted_volume_fails(session):
    volume_id = _volume(session, encrypted=False)

    results = scan_ebs_checks(session)

    finding = one_check(results, "EBS_NO_ENCRYPTION")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == volume_id


@mock_aws
def test_private_snapshot_passes(session):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    volume_id = _volume(session, encrypted=True)
    snapshot_id = ec2.create_snapshot(VolumeId=volume_id, Description="private")["SnapshotId"]

    results = scan_ebs_checks(session)

    assert _for_resource(results, "EBS_SNAPSHOT_NOT_PUBLIC", snapshot_id).status == CheckStatus.PASS


@mock_aws
def test_publicly_shared_snapshot_is_critical(session):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    volume_id = _volume(session, encrypted=False)
    snapshot_id = ec2.create_snapshot(VolumeId=volume_id, Description="oops")["SnapshotId"]

    ec2.modify_snapshot_attribute(
        SnapshotId=snapshot_id,
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )

    results = scan_ebs_checks(session)

    finding = _for_resource(results, "EBS_SNAPSHOT_PUBLIC", snapshot_id)
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.CRITICAL


@mock_aws
def test_account_with_no_volumes_yields_no_volume_checks(session):
    results = scan_ebs_checks(session)

    # Only volume checks can be asserted as empty -- moto seeds no volumes, but it
    # does seed AMI snapshots (see module docstring), so snapshot results won't be.
    assert not by_check(results, "EBS_ENCRYPTION")
    assert not by_check(results, "EBS_NO_ENCRYPTION")

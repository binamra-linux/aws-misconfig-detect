import pytest
from moto import mock_aws

from tests.conftest import AWS_REGION, by_check, one_check

from backend.detectors.sg_detector import scan_security_groups_checks
from backend.models import CheckStatus, Severity


def _open_group(session, port, cidr="0.0.0.0/0", protocol="tcp"):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    group_id = ec2.create_security_group(
        GroupName="exposed", Description="test", VpcId=vpc["VpcId"]
    )["GroupId"]

    permission = {"IpProtocol": protocol, "FromPort": port, "ToPort": port}
    if ":" in cidr:
        permission["Ipv6Ranges"] = [{"CidrIpv6": cidr}]
    else:
        permission["IpRanges"] = [{"CidrIp": cidr}]

    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[permission])
    return group_id


def _sg_port_checks(results, group_id, port):
    return [
        r
        for r in by_check(results, "SG_OPEN_SENSITIVE_PORT")
        if r.resource_id == group_id and r.detail.get("port") == port
    ]


@mock_aws
@pytest.mark.parametrize("port", [22, 3389, 3306, 5432])
def test_sensitive_port_open_to_world_is_critical(session, port):
    group_id = _open_group(session, port)

    results = scan_security_groups_checks(session)
    matches = _sg_port_checks(results, group_id, port)

    assert len(matches) == 1
    assert matches[0].status == CheckStatus.FAIL
    assert matches[0].severity == Severity.CRITICAL
    assert "0.0.0.0/0" in matches[0].detail["public_cidrs"]


@mock_aws
def test_ipv6_public_cidr_is_detected(session):
    group_id = _open_group(session, 22, cidr="::/0")

    results = scan_security_groups_checks(session)
    matches = _sg_port_checks(results, group_id, 22)

    assert matches[0].status == CheckStatus.FAIL
    assert "::/0" in matches[0].detail["public_cidrs"]


@mock_aws
def test_port_open_to_private_cidr_passes(session):
    group_id = _open_group(session, 22, cidr="10.0.0.0/8")

    results = scan_security_groups_checks(session)
    matches = _sg_port_checks(results, group_id, 22)

    # Restricted to a private range -- exposed to the VPC, not the internet.
    assert matches[0].status == CheckStatus.PASS


@mock_aws
def test_non_sensitive_port_is_not_flagged(session):
    group_id = _open_group(session, 8080)

    results = scan_security_groups_checks(session)

    # 8080 isn't in the sensitive set, so every sensitive port should still pass.
    for r in _sg_port_checks(results, group_id, 22):
        assert r.status == CheckStatus.PASS
    assert not _sg_port_checks(results, group_id, 8080)


@mock_aws
def test_every_sensitive_port_gets_a_result(session):
    group_id = _open_group(session, 22)

    results = scan_security_groups_checks(session)
    ports = {
        r.detail["port"] for r in by_check(results, "SG_OPEN_SENSITIVE_PORT") if r.resource_id == group_id
    }

    # PASS results matter too -- they're what makes "checks performed" a real
    # denominator on the Resources tab rather than a count of failures.
    assert ports == {22, 3389, 3306, 5432}


@mock_aws
def test_default_security_group_with_rules_is_flagged(session):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    # Every VPC gets a 'default' group automatically; moto gives it an egress-all rule.
    ec2.create_vpc(CidrBlock="10.0.0.0/16")

    results = scan_security_groups_checks(session)
    defaults = by_check(results, "SG_DEFAULT_ALLOWS_TRAFFIC")

    assert defaults, "expected a default-security-group check"
    flagged = [d for d in defaults if d.status == CheckStatus.FAIL]
    assert flagged
    assert flagged[0].severity == Severity.MEDIUM


@mock_aws
def test_default_security_group_with_no_rules_passes(session):
    ec2 = session.client("ec2", region_name=AWS_REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

    default = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]

    # Strip the default egress-all rule so the group truly allows nothing.
    if default.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(
            GroupId=default["GroupId"], IpPermissions=default["IpPermissionsEgress"]
        )

    results = scan_security_groups_checks(session)
    match = one_check(
        [r for r in results if r.resource_id == default["GroupId"]], "SG_DEFAULT_ALLOWS_TRAFFIC"
    )

    assert match.status == CheckStatus.PASS

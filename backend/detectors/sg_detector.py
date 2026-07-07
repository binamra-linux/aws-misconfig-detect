"""
Read-only security group misconfiguration checks:
  - inbound rules open to 0.0.0.0/0 or ::/0 on sensitive ports:
    22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL)

Only scans the single region the session is configured for (AWS_REGION) --
security groups are region-scoped, so multi-region accounts should re-run
with AWS_REGION set to each region of interest.

Required IAM permissions (read-only):
  ec2:DescribeSecurityGroups
"""

from typing import Any, Dict, List, Optional, Set

import boto3
from botocore.exceptions import ClientError

from backend.models import Finding, Severity

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _port_in_range(from_port: Optional[int], to_port: Optional[int], port: int) -> bool:
    if from_port is None or to_port is None:
        return True  # no port bounds specified -> applies to all ports
    return from_port <= port <= to_port


def _public_cidrs(permission: Dict[str, Any]) -> Set[str]:
    cidrs = {r["CidrIp"] for r in permission.get("IpRanges", []) if r.get("CidrIp") in PUBLIC_CIDRS}
    cidrs |= {r["CidrIpv6"] for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") in PUBLIC_CIDRS}
    return cidrs


def _exposed_ports(security_group: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    exposed: Dict[int, Dict[str, Any]] = {}

    for permission in security_group.get("IpPermissions", []):
        public_cidrs = _public_cidrs(permission)
        if not public_cidrs:
            continue

        protocol = permission.get("IpProtocol", "-1")
        if protocol not in ("-1", "tcp"):
            continue  # sensitive services here are all TCP-based

        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        for port, service in SENSITIVE_PORTS.items():
            if _port_in_range(from_port, to_port, port):
                entry = exposed.setdefault(port, {"service": service, "cidrs": set(), "protocol": protocol})
                entry["cidrs"] |= public_cidrs

    return exposed


def _check_security_group(security_group: Dict[str, Any], region: str) -> List[Finding]:
    group_id = security_group["GroupId"]
    group_name = security_group.get("GroupName", group_id)

    findings = []
    for port, info in _exposed_ports(security_group).items():
        findings.append(Finding(
            resource_id=group_id,
            resource_type="SecurityGroup",
            check_type="SG_OPEN_SENSITIVE_PORT",
            severity=Severity.CRITICAL,
            description=(
                f"Security group '{group_name}' ({group_id}) allows inbound {info['service']} "
                f"(port {port}) from {', '.join(sorted(info['cidrs']))}."
            ),
            detail={
                "group_name": group_name,
                "port": port,
                "service": info["service"],
                "protocol": info["protocol"],
                "public_cidrs": sorted(info["cidrs"]),
            },
            region=region,
        ))
    return findings


def scan_security_groups(session: Optional[boto3.Session] = None) -> List[Finding]:
    session = session or boto3.Session()
    ec2 = session.client("ec2")
    region = ec2.meta.region_name

    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        return [Finding(
            resource_id=region or "unknown",
            resource_type="SecurityGroup",
            check_type="SCAN_ERROR",
            severity=Severity.LOW,
            description=f"Could not scan security groups in {region}: {e.response['Error']['Code']}",
            detail={"error": str(e)},
            region=region,
        )]

    findings: List[Finding] = []
    for group in groups:
        findings.extend(_check_security_group(group, region))
    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_security_groups(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))

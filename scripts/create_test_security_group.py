"""
Creates a security group with SSH (port 22) open to 0.0.0.0/0, in the
account's default VPC, so you can validate the security-group detector
end-to-end.

This makes real, write-level changes to your AWS account. Run
destroy_test_security_group.py to clean it up when you're done.

Usage:
    python -m scripts.create_test_security_group
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner import build_session


def _default_vpc_id(ec2) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        raise RuntimeError("No default VPC found in this region -- create/specify a VPC manually.")
    return vpcs[0]["VpcId"]


def create_security_group(session) -> str:
    """Creates a security group with SSH open to 0.0.0.0/0 and returns its group ID."""
    ec2 = session.client("ec2")

    vpc_id = _default_vpc_id(ec2)
    group_name = f"awsdetect-test-{int(time.time())}"

    print(f"Creating security group '{group_name}' in VPC {vpc_id}...")
    group_id = ec2.create_security_group(
        GroupName=group_name,
        Description="Deliberately misconfigured group for awsdetect testing",
        VpcId=vpc_id,
    )["GroupId"]

    print("Authorizing inbound SSH (port 22) from 0.0.0.0/0...")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "awsdetect test - public SSH"}],
        }],
    )

    return group_id


def main():
    group_id = create_security_group(build_session())

    print(f"\nDone. Security group '{group_id}' allows public SSH.")
    print("\nRun the detector:\n  python -m backend.detectors.sg_detector")
    print(f"\nWhen you're done testing, clean up with:\n  python -m scripts.destroy_test_security_group {group_id}")


if __name__ == "__main__":
    main()

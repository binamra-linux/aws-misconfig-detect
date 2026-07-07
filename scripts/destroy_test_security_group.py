"""
Deletes a test security group created by create_test_security_group.py.

Usage:
    python -m scripts.destroy_test_security_group <group-id>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner import build_session


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.destroy_test_security_group <group-id>")
        sys.exit(1)

    group_id = sys.argv[1]
    session = build_session()
    ec2 = session.client("ec2")

    group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    if not group.get("GroupName", "").startswith("awsdetect-test-"):
        confirm = input(
            f"'{group_id}' ({group.get('GroupName')}) doesn't look like a test group created "
            f"by this tool. Delete it anyway? [y/N] "
        )
        if confirm.strip().lower() != "y":
            print("Aborted.")
            sys.exit(1)

    print(f"Deleting security group '{group_id}'...")
    ec2.delete_security_group(GroupId=group_id)
    print("Done.")


if __name__ == "__main__":
    main()

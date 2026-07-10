"""
Deletes a test IAM user created by create_test_iam_user.py, removing its
inline/attached policies, login profile, MFA devices, and access keys first
(IAM requires a user to be fully detached before it can be deleted).

Usage:
    python -m scripts.destroy_test_iam_user <user-name>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from botocore.exceptions import ClientError

from backend.scanner import build_session


def destroy_iam_user(session, user_name: str) -> None:
    iam = session.client("iam")

    print(f"Removing inline policies from '{user_name}'...")
    for policy_name in iam.list_user_policies(UserName=user_name)["PolicyNames"]:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)

    print(f"Detaching managed policies from '{user_name}'...")
    for policy in iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]:
        iam.detach_user_policy(UserName=user_name, PolicyArn=policy["PolicyArn"])

    print(f"Deleting login profile for '{user_name}' (if any)...")
    try:
        iam.delete_login_profile(UserName=user_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

    print(f"Deactivating MFA devices for '{user_name}' (if any)...")
    for device in iam.list_mfa_devices(UserName=user_name)["MFADevices"]:
        iam.deactivate_mfa_device(UserName=user_name, SerialNumber=device["SerialNumber"])

    print(f"Deleting access keys for '{user_name}'...")
    for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])

    print(f"Deleting user '{user_name}'...")
    iam.delete_user(UserName=user_name)


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.destroy_test_iam_user <user-name>")
        sys.exit(1)

    user_name = sys.argv[1]
    if not user_name.startswith("awsdetect-test-"):
        confirm = input(
            f"'{user_name}' doesn't look like a test user created by this tool. "
            f"Delete it anyway? [y/N] "
        )
        if confirm.strip().lower() != "y":
            print("Aborted.")
            sys.exit(1)

    destroy_iam_user(build_session(), user_name)
    print("Done.")


if __name__ == "__main__":
    main()

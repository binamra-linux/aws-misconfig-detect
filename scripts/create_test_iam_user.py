"""
Creates a deliberately misconfigured IAM user so you can validate the IAM
detector end-to-end:
  - an inline policy granting Action:"*" on Resource:"*"
  - a console password with no MFA device attached
  - an access key (won't show as "unused" until IAM_UNUSED_KEY_DAYS has
    elapsed -- set IAM_UNUSED_KEY_DAYS=0 in .env to test that check immediately)

This makes real, write-level changes to your AWS account. Run
destroy_test_iam_user.py to clean it up when you're done.

Usage:
    python -m scripts.create_test_iam_user
"""

import json
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner import build_session

OVERLY_PERMISSIVE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def main():
    session = build_session()
    iam = session.client("iam")
    user_name = f"awsdetect-test-{int(time.time())}"

    print(f"Creating IAM user '{user_name}'...")
    iam.create_user(UserName=user_name)

    print("Attaching an overly permissive inline policy (Action:*, Resource:*)...")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="OverlyPermissiveForTesting",
        PolicyDocument=json.dumps(OVERLY_PERMISSIVE_POLICY),
    )

    password = f"Test-{secrets.token_urlsafe(12)}!"
    print("Creating a console login profile (password) with no MFA device...")
    iam.create_login_profile(UserName=user_name, Password=password, PasswordResetRequired=True)

    print("Creating an access key...")
    key = iam.create_access_key(UserName=user_name)["AccessKey"]

    print(f"\nDone. '{user_name}' now has:")
    print("  - an overly permissive inline policy")
    print("  - a console password with no MFA")
    print(f"  - access key {key['AccessKeyId']} (see note above about testing IAM_UNUSED_ACCESS_KEY)")
    print("\nRun the detector:\n  python -m backend.detectors.iam_detector")
    print(f"\nWhen you're done testing, clean up with:\n  python -m scripts.destroy_test_iam_user {user_name}")


if __name__ == "__main__":
    main()

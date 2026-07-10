"""
Creates all three throwaway misconfigured resources at once -- an S3 bucket,
an IAM user, and a security group -- so you can validate every detector
against real findings in one step instead of running three separate scripts.

Resource identifiers are written to scripts/.test_fixtures.json so
destroy_all_test_vulnerabilities.py can find and remove them automatically --
no copy-pasting bucket names/IDs required.

This makes real, write-level changes to your AWS account. See the "Testing
against a throwaway ..." sections in the README for the exact temporary
write permissions each piece needs (S3, IAM, and EC2 respectively) -- your
scanning IAM user needs all three at once to run this script.

Usage:
    python -m scripts.create_all_test_vulnerabilities
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner import build_session
from scripts.create_test_bucket import create_bucket
from scripts.create_test_iam_user import create_iam_user
from scripts.create_test_security_group import create_security_group

STATE_FILE = Path(__file__).resolve().parent / ".test_fixtures.json"


def main():
    session = build_session()
    state = {}

    print("=== S3 bucket ===")
    state["bucket"] = create_bucket(session)

    print("\n=== IAM user ===")
    state["iam_user"] = create_iam_user(session)

    print("\n=== Security group ===")
    state["security_group"] = create_security_group(session)

    STATE_FILE.write_text(json.dumps(state, indent=2))

    print("\nDone. Created:")
    print(f"  - S3 bucket:       {state['bucket']}")
    print(f"  - IAM user:        {state['iam_user']}")
    print(f"  - Security group:  {state['security_group']}")
    print("\nRun a full scan to see all the findings:\n  python -m backend.scanner")
    print(
        "\nWhen you're done testing, clean up everything with:\n"
        "  python -m scripts.destroy_all_test_vulnerabilities"
    )


if __name__ == "__main__":
    main()

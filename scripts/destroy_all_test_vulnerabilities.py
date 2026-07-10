"""
Removes everything created by create_all_test_vulnerabilities.py, reading
resource identifiers back from scripts/.test_fixtures.json -- no arguments
needed.

Usage:
    python -m scripts.destroy_all_test_vulnerabilities
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner import build_session
from scripts.destroy_test_bucket import destroy_bucket
from scripts.destroy_test_iam_user import destroy_iam_user
from scripts.destroy_test_security_group import destroy_security_group

STATE_FILE = Path(__file__).resolve().parent / ".test_fixtures.json"


def main():
    if not STATE_FILE.exists():
        print(f"No {STATE_FILE.name} found -- nothing to clean up (already removed, or never created).")
        sys.exit(1)

    state = json.loads(STATE_FILE.read_text())
    session = build_session()

    if state.get("bucket"):
        print(f"=== Destroying S3 bucket {state['bucket']} ===")
        destroy_bucket(session, state["bucket"])

    if state.get("iam_user"):
        print(f"\n=== Destroying IAM user {state['iam_user']} ===")
        destroy_iam_user(session, state["iam_user"])

    if state.get("security_group"):
        print(f"\n=== Destroying security group {state['security_group']} ===")
        destroy_security_group(session, state["security_group"])

    STATE_FILE.unlink()
    print("\nDone. All test vulnerabilities removed.")


if __name__ == "__main__":
    main()

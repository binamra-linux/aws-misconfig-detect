"""
Empties and deletes a test bucket created by create_test_bucket.py.

Usage:
    python -m scripts.destroy_test_bucket <bucket-name>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from botocore.exceptions import ClientError

from backend.scanner import build_session


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.destroy_test_bucket <bucket-name>")
        sys.exit(1)

    bucket_name = sys.argv[1]
    if not bucket_name.startswith("awsdetect-test-"):
        confirm = input(
            f"'{bucket_name}' doesn't look like a test bucket created by this tool. "
            f"Delete it anyway? [y/N] "
        )
        if confirm.strip().lower() != "y":
            print("Aborted.")
            sys.exit(1)

    session = build_session()
    bucket = session.resource("s3").Bucket(bucket_name)

    print(f"Emptying bucket '{bucket_name}'...")
    bucket.objects.all().delete()
    try:
        # Only needed for buckets that had versioning enabled; the test
        # bucket doesn't, so skip quietly if s3:ListBucketVersions isn't granted.
        bucket.object_versions.all().delete()
    except ClientError as e:
        if e.response["Error"]["Code"] != "AccessDenied":
            raise
        print("  (skipping object-version cleanup — s3:ListBucketVersions not granted, not needed for this bucket)")

    print(f"Deleting bucket '{bucket_name}'...")
    bucket.delete()
    print("Done.")


if __name__ == "__main__":
    main()

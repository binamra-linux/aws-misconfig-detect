"""
Creates a deliberately misconfigured S3 bucket in YOUR account so you can
validate the detector end-to-end: public read access + versioning disabled.

This makes real, billable (though free-tier) changes to your AWS account.
Run destroy_test_bucket.py to clean it up when you're done.

Usage:
    python -m scripts.create_test_bucket
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config
from backend.scanner import build_session

PUBLIC_READ_POLICY = """{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "PublicReadForTesting",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::{bucket}/*"
    }}
  ]
}}"""


def main():
    session = build_session()
    s3 = session.client("s3")
    region = config.AWS_REGION
    bucket_name = f"awsdetect-test-{int(time.time())}"

    print(f"Creating bucket '{bucket_name}' in {region}...")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )

    print("Disabling the public access block (so a public policy can take effect)...")
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    print("Attaching a public-read bucket policy...")
    s3.put_bucket_policy(Bucket=bucket_name, Policy=PUBLIC_READ_POLICY.format(bucket=bucket_name))

    print(f"\nDone. '{bucket_name}' is now public with versioning disabled.")
    print(
        "Note: AWS has enabled SSE-S3 default encryption on all new buckets "
        "automatically since Jan 2023, so S3_NO_ENCRYPTION likely won't fire here."
    )
    print("\nRun the detector:\n  python -m backend.detectors.s3_detector")
    print(f"\nWhen you're done testing, clean up with:\n  python -m scripts.destroy_test_bucket {bucket_name}")


if __name__ == "__main__":
    main()

# aws-misconfig-detect

AI-assisted AWS cloud misconfiguration detection and remediation tool, built for
resource-constrained IT startups. Scans a live AWS account read-only, structures
findings as JSON, and uses Groq to generate plain-language risk explanations and
concrete remediation steps for each one. Results are shown in a Streamlit dashboard.

## Status

- ✅ S3: public read/write access, missing encryption, missing versioning
- ✅ IAM: overly permissive policies, missing MFA, unused access keys
- ✅ Security groups: 0.0.0.0/0 / ::/0 on ports 22/3389/3306/5432

## Project layout

```
backend/
  config.py              # loads AWS/Groq settings from env vars / .env
  models.py              # Finding / Severity data model
  scanner.py             # orchestrates all detectors
  detectors/
    s3_detector.py         # implemented
    iam_detector.py        # implemented
    sg_detector.py         # implemented
  ai/
    groq_client.py         # Groq (OpenAI-compatible) explanation generator
dashboard/
  app.py                   # Streamlit UI
```

## Setup

1. Create a virtualenv and install dependencies:

   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy `.env.example` to `.env` and fill in your values:

   ```bash
   cp .env.example .env
   ```

   - **AWS**: either set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env`,
     set `AWS_PROFILE` to a profile already configured in `~/.aws/credentials`,
     or leave both blank to use an existing default profile / instance role.
     **Never commit real keys** — `.env` is already git-ignored.
   - **Groq**: get an API key from https://console.groq.com and set `GROQ_API_KEY`.

3. Create a read-only IAM user/role for scanning. Minimum policy for the current
   (S3 + IAM + security groups) scope:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:ListAllMyBuckets",
           "s3:GetBucketLocation",
           "s3:GetBucketAcl",
           "s3:GetBucketPolicyStatus",
           "s3:GetEncryptionConfiguration",
           "s3:GetBucketVersioning",
           "iam:ListUsers",
           "iam:ListUserPolicies",
           "iam:GetUserPolicy",
           "iam:ListAttachedUserPolicies",
           "iam:ListGroupsForUser",
           "iam:ListGroupPolicies",
           "iam:GetGroupPolicy",
           "iam:ListAttachedGroupPolicies",
           "iam:GetPolicy",
           "iam:GetPolicyVersion",
           "iam:GetLoginProfile",
           "iam:ListMFADevices",
           "iam:ListAccessKeys",
           "iam:GetAccessKeyLastUsed",
           "ec2:DescribeSecurityGroups"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

   This is intentionally read-only — the tool never modifies your account.

## Running the scanner standalone

From the project root (so `backend` is importable as a package):

```bash
python -m backend.detectors.s3_detector   # S3 findings only, printed as JSON
python -m backend.detectors.iam_detector  # IAM findings only, printed as JSON
python -m backend.detectors.sg_detector   # security-group findings only, printed as JSON
python -m backend.scanner                 # full scan (S3 + IAM + security groups)
```

## Testing against a throwaway bucket

If you don't already have a misconfigured bucket to test against, `scripts/create_test_bucket.py`
creates one for you: public read access + versioning disabled (a `awsdetect-test-<timestamp>` bucket).

This is a **write** operation, so it needs more than the read-only policy above — either
attach `AmazonS3FullAccess` temporarily to your test IAM user, or add
`s3:CreateBucket`, `s3:PutBucketPolicy`, `s3:PutBucketPublicAccessBlock`,
`s3:DeleteBucket`, `s3:DeleteObject` to it.

```bash
python -m scripts.create_test_bucket
# ... prints the bucket name, then:
python -m backend.detectors.s3_detector
# ... should show S3_PUBLIC_READ and S3_VERSIONING_DISABLED findings for it

# when done:
python -m scripts.destroy_test_bucket <bucket-name>
```

Note: AWS has applied default SSE-S3 encryption to all new buckets automatically since
January 2023, so `S3_NO_ENCRYPTION` generally won't fire on a freshly created bucket —
that check is still useful for older buckets that predate the change or had encryption
explicitly removed.

## Testing against a throwaway IAM user

`scripts/create_test_iam_user.py` creates an `awsdetect-test-<timestamp>` IAM user with:
an inline policy granting `Action:"*"`/`Resource:"*"`, a console password with no MFA
device, and an access key.

This also needs write permissions beyond the read-only policy above — either attach
`IAMFullAccess` temporarily to your test IAM user, or scope an inline policy to
`iam:CreateUser`, `iam:PutUserPolicy`, `iam:CreateLoginProfile`, `iam:CreateAccessKey`,
`iam:DeleteUserPolicy`, `iam:DetachUserPolicy`, `iam:DeleteLoginProfile`,
`iam:DeactivateMFADevice`, `iam:DeleteAccessKey`, `iam:DeleteUser` on resources matching
`arn:aws:iam::*:user/awsdetect-test-*`.

```bash
python -m scripts.create_test_iam_user
# ... prints the user name, then:
python -m backend.detectors.iam_detector
# ... should show IAM_OVERLY_PERMISSIVE_POLICY and IAM_NO_MFA findings for it

# when done:
python -m scripts.destroy_test_iam_user <user-name>
```

Note: `IAM_UNUSED_ACCESS_KEY` won't fire on a freshly created key, since it hasn't been
inactive for `IAM_UNUSED_KEY_DAYS` (default 90) yet. Set `IAM_UNUSED_KEY_DAYS=0` in `.env`
temporarily to see that check trigger immediately, then reset it back to 90 for real scans.

## Testing against a throwaway security group

`scripts/create_test_security_group.py` creates an `awsdetect-test-<timestamp>` security
group in your account's default VPC with SSH (port 22) open to `0.0.0.0/0`.

This also needs write permissions beyond the read-only policy above — either attach
`AmazonEC2FullAccess` temporarily to your test IAM user, or scope an inline policy to
`ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:DeleteSecurityGroup`,
and `ec2:DescribeVpcs` (needed by the script to find the default VPC).

```bash
python -m scripts.create_test_security_group
# ... prints the group ID, then:
python -m backend.detectors.sg_detector
# ... should show an SG_OPEN_SENSITIVE_PORT finding for port 22

# when done:
python -m scripts.destroy_test_security_group <group-id>
```

Note: the detector only scans the region your session is configured for (`AWS_REGION`).
Security groups are region-scoped, so re-run with a different `AWS_REGION` to check other
regions.

## Running the dashboard

```bash
streamlit run dashboard/app.py
```

Click **Run Scan**, then expand any finding to see its raw AWS detail and
request an AI-generated risk explanation + remediation steps from Groq.

## Finding shape

Every finding follows this JSON structure:

```json
{
  "resource_id": "my-bucket-name",
  "resource_type": "S3Bucket",
  "check_type": "S3_PUBLIC_READ",
  "severity": "HIGH",
  "description": "S3 bucket 'my-bucket-name' is publicly accessible...",
  "detail": { "...raw AWS API response fields..." },
  "region": "us-east-1"
}
```

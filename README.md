# CloudSentinel

AI-assisted AWS cloud misconfiguration detection and remediation tool, built for
resource-constrained IT startups. Scans a live AWS account read-only, structures
findings as JSON, and uses Groq to generate plain-language risk explanations and
concrete remediation steps for each one.

Two front ends share the same detection backend:
- A **Streamlit dashboard** (`dashboard/app.py`) — quick, single-file, good for a fast check.
- A **React web app** (`frontend/` + `api/`) — six tabs (Overview, Findings, Resources,
  Compliance, History, Settings), a security score, scan history trends, and a PDF
  report export. This is the more polished, thesis-presentation-facing UI.

## Status

- ✅ S3: public read/write access, missing encryption, missing versioning
- ✅ IAM: overly permissive policies, missing MFA, unused access keys, root account MFA/access keys
- ✅ Security groups: 0.0.0.0/0 / ::/0 on ports 22/3389/3306/5432
- ✅ EBS: unencrypted volumes, publicly shared snapshots
- ✅ RDS: publicly accessible instances, missing storage encryption, publicly shared manual snapshots
- ✅ CloudTrail: no multi-region trail actively logging, log file validation disabled

Every check records **both** a pass and a fail outcome internally (see "CheckResult
vs Finding" below), which is what powers the Resources tab, the Compliance tab, and
the security score.

## Project layout

```
backend/
  config.py              # loads AWS/Groq settings from env vars / .env
  models.py              # Finding / CheckResult / Severity data model
  scanner.py             # run_scan() (findings only) + run_full_scan() (all checks)
  scoring.py             # server-side security score (single source of truth)
  history.py             # scan history persistence (data/scan_history.json)
  detectors/
    s3_detector.py         # implemented
    iam_detector.py        # implemented
    sg_detector.py         # implemented
    ebs_detector.py        # implemented
    rds_detector.py        # implemented
    cloudtrail_detector.py # implemented
  ai/
    groq_client.py         # Groq (OpenAI-compatible) explanation generator
api/
  main.py                  # FastAPI backend for the React web app
frontend/                  # Vite + React + TypeScript + Tailwind + shadcn/ui web app
dashboard/
  app.py                   # Streamlit UI (alternative front end, still works standalone)
data/
  scan_history.json        # gitignored, created on first scan via the web app
```

## Setup

1. Python dependencies:

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
     set `AWS_PROFILE` to a profile already configured in `~/.aws/credentials`
     (including an `aws sso login`-based profile), or leave both blank to use an
     existing default profile / instance role. **Never commit real keys** — `.env`
     is already git-ignored.
   - **Groq**: get an API key from https://console.groq.com and set `GROQ_API_KEY`.

3. Create a read-only IAM user/role for scanning. Minimum policy for the current
   (S3 + IAM + security groups + EBS + RDS + CloudTrail) scope:

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
           "iam:GetAccountSummary",
           "ec2:DescribeSecurityGroups",
           "ec2:DescribeVolumes",
           "ec2:DescribeSnapshots",
           "ec2:DescribeSnapshotAttribute",
           "rds:DescribeDBInstances",
           "rds:DescribeDBSnapshots",
           "rds:DescribeDBSnapshotAttributes",
           "cloudtrail:DescribeTrails",
           "cloudtrail:GetTrailStatus"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

   This is intentionally read-only — the tool never modifies your account. If you
   run the `scripts/create_test_*.py` fixtures (see below), they need extra
   *temporary* write permissions of their own — remove those again afterwards.

4. **Only if you want the React web app** (the Streamlit dashboard needs nothing
   beyond step 1): install Node.js. This project uses `nvm` so it doesn't need
   `sudo`:

   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
   export NVM_DIR="$HOME/.nvm" && \. "$NVM_DIR/nvm.sh"
   nvm install --lts

   cd frontend
   npm install
   ```

## Running the scanner standalone

From the project root (so `backend` is importable as a package):

```bash
python -m backend.detectors.s3_detector   # S3 findings only, printed as JSON
python -m backend.detectors.iam_detector  # IAM findings only, printed as JSON
python -m backend.detectors.sg_detector   # security-group findings only, printed as JSON
python -m backend.scanner                 # full scan (S3 + IAM + security groups)
```

## Running the Streamlit dashboard

```bash
streamlit run dashboard/app.py
```

Click **Run Scan**, then expand any finding to see its raw AWS detail and
request an AI-generated risk explanation + remediation steps from Groq.

## Running the React web app

Two processes: the FastAPI backend and the Vite dev server (which proxies `/api/*`
to it, so there's no CORS setup needed).

```bash
# terminal 1
python -m uvicorn api.main:app --reload --port 8000

# terminal 2
cd frontend
npm run dev -- --port 5173
```

Open http://localhost:5173. The FastAPI backend's interactive docs are at
http://localhost:8000/docs.

**Single-process demo mode** (what to use for an actual presentation/defense —
no separate dev server, no internet dependency for the UI itself, everything on
one port):

```bash
cd frontend && npm run build && cd ..
python -m uvicorn api.main:app --port 8000
```

Open http://localhost:8000 — FastAPI serves the built React app directly
(`frontend/dist/`) alongside the API.

### The six tabs

- **Overview** — security score gauge, severity breakdown, per-resource-type
  counts, latest findings.
- **Findings** — searchable/filterable table of failures only, click a row to
  expand it inline for raw detail + an on-demand AI explanation, "Download
  Report" for a PDF export.
- **Resources** — every check performed against every resource, pass *and*
  fail, not just misconfigurations.
- **Compliance** — findings grouped by CIS AWS Foundations Benchmark v1.5.0
  control (best-effort mapping — see caveat below).
- **History** — score and finding-count trend across past scans, persisted to
  `data/scan_history.json`.
- **Settings** — current AWS/Groq config (read-only) plus a live-editable
  "unused access key" threshold that takes effect on the next scan with no
  restart needed.

## CheckResult vs Finding

Each detector's internal checks record a `CheckResult` (pass or fail) for every
check performed, not just failures. `Finding` (what the Streamlit dashboard, the
`/api/findings` endpoint, and `run_scan()` all use) is just the FAIL subset —
`CheckResult.to_finding()` returns `None` for a pass. `run_full_scan()` /
`/api/resources` expose the complete picture, which is what makes the Resources
tab and the Compliance tab possible without a separate resource inventory pass.

## Security score

`backend/scoring.py` computes a severity-weighted heuristic (deduct points per
finding — CRITICAL −25, HIGH −15, MEDIUM −8, LOW −3 — floored at 0), **not** a
literal "% of checks passed." It's the single source of truth for both the live
Overview card and the persisted History records, so they can't disagree about
the score for a given scan.

## Compliance mapping caveat

`frontend/src/lib/compliance.ts` maps check types to **CIS AWS Foundations
Benchmark v1.5.0** control numbers. Control numbers have shifted across
benchmark releases (v1.2/v1.4/v1.5/v3.0) — this is a best-effort mapping for a
single cited version, not verified against the official PDF. Checks without a
confident, dedicated control (S3 checks, and the MySQL/PostgreSQL ports in
`SG_OPEN_SENSITIVE_PORT` — only 22/3389 are explicitly named in the benchmark)
are labeled "N/A" rather than given a fabricated number. Verify against the
official benchmark document before citing any of this formally.

## Testing against all three at once (recommended)

`scripts/create_all_test_vulnerabilities.py` creates the S3 bucket, IAM user, and
security group described in the three sections below all in one step, and writes
their identifiers to `scripts/.test_fixtures.json` (gitignored) so you don't have to
copy-paste bucket names/IDs to clean up afterwards.

This needs the union of all three sections' temporary write permissions at once — see
below for the exact actions, or just attach `AmazonS3FullAccess` + `IAMFullAccess` +
`AmazonEC2FullAccess` temporarily if you want the simplest (broadest) path. **Remove
whatever you attach again once you're done testing.**

```bash
python -m scripts.create_all_test_vulnerabilities
# creates a public S3 bucket, an overly-permissive MFA-less IAM user, and a
# security group with SSH open to 0.0.0.0/0

python -m backend.scanner
# should show 6 findings: S3_PUBLIC_READ, S3_VERSIONING_DISABLED,
# IAM_OVERLY_PERMISSIVE_POLICY, IAM_NO_MFA (x2 -- the test user and your real
# account if it also lacks MFA), SG_OPEN_SENSITIVE_PORT

# when done:
python -m scripts.destroy_all_test_vulnerabilities
```

Use the individual `create_test_bucket.py` / `create_test_iam_user.py` /
`create_test_security_group.py` scripts below instead if you only want to exercise
one detector at a time.

## Testing against a throwaway bucket

If you don't already have a misconfigured bucket to test against, `scripts/create_test_bucket.py`
creates one for you: public read access + versioning disabled (a `awsdetect-test-<timestamp>` bucket).

This is a **write** operation, so it needs more than the read-only policy above — either
attach `AmazonS3FullAccess` temporarily to your test IAM user, or add
`s3:CreateBucket`, `s3:PutBucketPolicy`, `s3:PutBucketPublicAccessBlock`,
`s3:DeleteBucket`, `s3:DeleteObject` to it. **Remove the temporary policy again once
you're done testing.**

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
`arn:aws:iam::*:user/awsdetect-test-*`. **This scoping means the policy can only clean
up `awsdetect-test-*` users, not modify your own real IAM user — remove it manually via
the console once you're done testing.**

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
(CLI/Streamlit) or via the web app's **Settings** tab (takes effect immediately, no
restart) to see that check trigger right away, then reset it back to 90 for real scans.

`ROOT_NO_MFA` and `ROOT_ACCESS_KEYS_PRESENT` check your account's actual root user via
`iam:GetAccountSummary` -- there's no safe way to fabricate a test fixture for these (you
shouldn't create root access keys just to test), so they just reflect real account state.
If root already has MFA and no access keys, they simply won't fire, which is correct.

## Testing against a throwaway security group

`scripts/create_test_security_group.py` creates an `awsdetect-test-<timestamp>` security
group in your account's default VPC with SSH (port 22) open to `0.0.0.0/0`.

This also needs write permissions beyond the read-only policy above — either attach
`AmazonEC2FullAccess` temporarily to your test IAM user, or scope an inline policy to
`ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:DeleteSecurityGroup`,
and `ec2:DescribeVpcs` (needed by the script to find the default VPC). **Remove the
temporary policy again once you're done testing.**

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

## Finding shape

Every finding (a *failed* check) follows this JSON structure:

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

A `CheckResult` (from `run_full_scan()` / `GET /api/resources`) is the same shape
plus a `status` field (`"PASS"` or `"FAIL"`) and a nullable `severity` (`null` on
a pass).

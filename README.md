# CloudSentinel

AI-assisted AWS cloud misconfiguration detection and remediation tool, built for
resource-constrained IT startups. Scans a live AWS account read-only, structures
findings as JSON, and uses Groq to generate plain-language risk explanations and
concrete remediation steps for each one.

Two front ends share the same detection backend:
- A **Streamlit dashboard** (`dashboard/app.py`) — quick, single-file, good for a fast check.
- A **React web app** (`frontend/` + `api/`) — login-protected, with seven tabs (Home,
  Overview, Findings, Resources, Compliance, History, Settings), a security score, live
  scan progress, scan history trends, one-click remediation, and a PDF report export.

## Quick start (Docker)

```bash
cp .env.example .env      # fill in AWS + Groq credentials
docker compose up
```

Open http://localhost:8000. The first account you create becomes the administrator;
registration closes automatically afterwards.

> Run a **single instance**. Scan state is held in process memory and the scheduler runs
> per-process, so a second replica would serve inconsistent findings and duplicate every
> scheduled scan (and every alert email).

## Status

Detection (all read-only):

- ✅ S3: account-level Block Public Access, public read/write, missing encryption, missing versioning
- ✅ IAM: overly permissive policies, missing MFA, unused access keys, root account MFA/access keys, weak password policy
- ✅ Security groups: 0.0.0.0/0 / ::/0 on ports 22/3389/3306/5432, default SG carrying rules
- ✅ EBS: unencrypted volumes, publicly shared snapshots
- ✅ RDS: publicly accessible instances, missing storage encryption, publicly shared manual snapshots
- ✅ CloudTrail: no multi-region trail actively logging, log file validation disabled

Platform:

- ✅ **Login** — multi-user accounts, PBKDF2-hashed passwords, httpOnly session cookie
- ✅ **Multi-region scanning** — regional detectors run across every enabled region, in parallel
- ✅ **Scheduled scans** — cron-driven background scans with email alerts on *new* findings
- ✅ **One-click remediation** — opt-in, off by default (see below)
- ✅ **Tests** — `pytest` + `moto`, no live AWS calls
- ✅ **Docker** — single-command deploy

Every check records **both** a pass and a fail outcome internally (see "CheckResult
vs Finding" below), which is what powers the Resources tab, the Compliance tab, and
the security score.

## Project layout

```
backend/
  config.py              # all settings, loaded from env vars / .env
  models.py              # Finding / CheckResult / Severity data model
  scanner.py             # region planning + run_scan() / run_full_scan()
  scan_service.py        # current-scan state + the single-scan lock (shared by API & scheduler)
  scoring.py             # server-side security score (single source of truth)
  history.py             # scan history persistence (data/scan_history.json)
  users.py               # login accounts, PBKDF2-hashed (data/users.json)
  scheduler.py           # cron-driven background scans (APScheduler)
  detectors/
    s3_detector.py         # + account-level Block Public Access
    iam_detector.py        # + password policy
    sg_detector.py         # + default security group
    ebs_detector.py
    rds_detector.py
    cloudtrail_detector.py
  remediation/
    __init__.py            # the ONLY code that writes to AWS; opt-in, off by default
  notify/
    email_client.py        # SMTP alerts for new findings
  ai/
    groq_client.py         # Groq (OpenAI-compatible) explanation generator
api/
  main.py                  # FastAPI: auth, scan (+SSE stream), findings, remediation
frontend/                  # Vite + React + TypeScript + Tailwind + shadcn/ui web app
dashboard/
  app.py                   # Streamlit UI (alternative front end, still works standalone)
tests/                     # pytest + moto; no live AWS calls
data/                      # gitignored
  scan_history.json        # created on first scan
  users.json               # created on first login
Dockerfile                 # multi-stage: builds the SPA, serves it from FastAPI
docker-compose.yml
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
           "iam:GetAccountPasswordPolicy",
           "s3:GetAccountPublicAccessBlock",
           "sts:GetCallerIdentity",
           "ec2:DescribeRegions",
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

   This is intentionally read-only — by default the tool never modifies your
   account. Extra permissions are needed only if you opt into
   [one-click remediation](#one-click-remediation-opt-in). If you run the
   `scripts/create_test_*.py` fixtures (see below), they need their own
   *temporary* write permissions — remove those again afterwards.

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

### The seven tabs

- **Home** — landing page: last scan summary, top issues needing attention, and
  shortcuts into every other section.
- **Overview** — security score gauge, severity breakdown, per-resource-type
  counts, latest findings.
- **Findings** — searchable/filterable table of failures only, click a row to
  expand it inline for raw detail, an on-demand AI explanation, and a one-click
  fix where one is available. "Download Report" exports a PDF.
- **Resources** — every check performed against every resource, pass *and*
  fail, not just misconfigurations.
- **Compliance** — findings grouped by CIS AWS Foundations Benchmark v1.5.0
  control (best-effort mapping — see caveat below).
- **History** — score and finding-count trend across past scans, persisted to
  `data/scan_history.json`.
- **Settings** — AWS/Groq/schedule/remediation status, a live-editable "unused
  access key" threshold, and a reset button that clears all scan data.

## Login

The web app requires a login. The **first** account created becomes the administrator,
and registration closes permanently after that — so the app isn't world-registrable if
you expose the port.

Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, stdlib only — no
native build deps) and stored in `data/users.json`. Plaintext passwords are never
stored or logged.

Sessions are a **signed, httpOnly cookie**, not a bearer token. That's forced by the
browser: `EventSource` (which powers the live scan-progress stream) cannot set an
`Authorization` header, so a cookie is the only scheme that authenticates the *whole*
API including the stream.

Set `SESSION_SECRET` in `.env` — otherwise a random one is generated at startup and
every session is invalidated on restart:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

If you serve over HTTPS, also set `SESSION_HTTPS_ONLY=true`. Leave it `false` on
plain-HTTP localhost — browsers silently drop `Secure` cookies over `http://`, which
looks like "login succeeds, then immediately logs out".

## Multi-region scanning

Set `AWS_REGIONS` in `.env`:

| Value | Behaviour |
|---|---|
| *(blank)* | Only `AWS_REGION`. The default — fast, no surprises. |
| `all` | Every region enabled on the account (needs `ec2:DescribeRegions`). |
| `us-east-1,eu-west-1` | Exactly those regions. |

Only the **regional** detectors (security groups, EBS, RDS) loop over regions; they run
in parallel. S3, IAM and CloudTrail are global and always scanned once.

CloudTrail deserves a note: `describe_trails()` returns *shadow trails* — replicas of
multi-region and organization trails from every other region — so a single call already
sees everything. Scanning it per-region would report the same trail N times.

## Scheduled scans and email alerts

```bash
SCAN_SCHEDULE_ENABLED=true
SCAN_SCHEDULE_CRON=0 2 * * *      # 02:00 daily

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=you@example.com
ALERT_TO=security@example.com,ops@example.com
```

Alerts fire only on findings that are **new since the previous scan**. An unchanged
backlog is never re-sent — a nightly email repeating the same twelve known issues is
how alerts get filtered into a folder and ignored.

A scheduled scan and a manual scan can never run at once: both go through the same
lock, and the scheduled one skips (rather than queues) if you're already scanning.

## One-click remediation (opt-in)

**Disabled by default.** CloudSentinel is read-only unless you explicitly turn this on —
that guarantee is worth more than the convenience, so it's an opt-in rather than a
default.

```bash
REMEDIATION_ENABLED=true
```

Fixes available today:

| Finding | What the fix does |
|---|---|
| `S3_PUBLIC_READ` / `S3_PUBLIC_WRITE` | Enables all four Block Public Access settings |
| `S3_NO_ENCRYPTION` | Enables default AES256 encryption |
| `S3_VERSIONING_DISABLED` | Enables versioning |
| `SG_OPEN_SENSITIVE_PORT` | Revokes **only** the public-internet rule for that port |
| `EBS_SNAPSHOT_PUBLIC` | Stops sharing the snapshot with all AWS accounts |
| `RDS_SNAPSHOT_PUBLIC` | Stops sharing the snapshot with all AWS accounts |
| `CLOUDTRAIL_LOG_VALIDATION_DISABLED` | Enables log file validation |

Every fix is a single, reversible call, and the UI shows the exact AWS API call and
asks you to confirm before it runs. **No fix deletes data** — buckets get *blocked*,
not emptied; snapshots get *unshared*, not removed; the security-group fix revokes only
the specific flagged rule and leaves every other rule alone.

This needs write permissions **in addition to** the read-only policy above — attach
this separately, and only if you want remediation:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:PutEncryptionConfiguration",
        "s3:PutBucketVersioning",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:ModifySnapshotAttribute",
        "rds:ModifyDBSnapshotAttribute",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    }
  ]
}
```

## Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

102 tests, using `moto` to mock AWS — **no live AWS calls and no credentials needed**.
`tests/conftest.py` force-neutralises `AWS_PROFILE` and injects fake credentials
specifically so that a developer with a real profile in their `.env` can't accidentally
have the suite hit their live account.

Two coverage gaps are documented honestly in the test files rather than papered over,
both caused by moto (not by the detectors):

- moto doesn't implement `s3:GetBucketPolicyStatus`, so only the **ACL-based** half of
  S3 public-access detection is covered; the policy-based half is verified against real
  AWS instead.
- moto's `get_account_summary()` hardcodes the root MFA/access-key values, so only one
  branch of each root-account check is reachable.

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

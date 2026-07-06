# aws-misconfig-detect

AI-assisted AWS cloud misconfiguration detection and remediation tool, built for
resource-constrained IT startups. Scans a live AWS account read-only, structures
findings as JSON, and uses Groq to generate plain-language risk explanations and
concrete remediation steps for each one. Results are shown in a Streamlit dashboard.

## Status

- ✅ S3: public read/write access, missing encryption, missing versioning
- ⏳ IAM: overly permissive policies, missing MFA, unused access keys (stub — phase 2)
- ⏳ Security groups: 0.0.0.0/0 on ports 22/3389/3306/5432 (stub — phase 3)

## Project layout

```
backend/
  config.py              # loads AWS/Groq settings from env vars / .env
  models.py              # Finding / Severity data model
  scanner.py             # orchestrates all detectors
  detectors/
    s3_detector.py        # implemented
    iam_detector.py        # stub, raises NotImplementedError
    sg_detector.py          # stub, raises NotImplementedError
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
   (S3-only) scope:

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
           "s3:GetBucketVersioning"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

   This is intentionally read-only — the tool never modifies your account. When
   IAM and security-group detectors are added, their required read-only actions
   are documented in the module docstrings.

## Running the scanner standalone

From the project root (so `backend` is importable as a package):

```bash
python -m backend.detectors.s3_detector   # S3 findings only, printed as JSON
python -m backend.scanner                 # full scan (currently == S3 only)
```

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

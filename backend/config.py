import os

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


# AWS — credentials themselves are picked up by boto3's default chain
# (env vars, ~/.aws/credentials, or an instance/role profile). We only
# need to know which named profile/region to use, if any.
AWS_PROFILE = os.getenv("AWS_PROFILE") or None
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Which regions the *regional* detectors (security groups, EBS, RDS) scan.
#   unset/empty -> just AWS_REGION (the original single-region behaviour)
#   "all"       -> every region enabled on the account (via ec2:DescribeRegions)
#   "a,b,c"     -> exactly those regions
# S3, IAM and CloudTrail are global and are always scanned once, regardless.
AWS_REGIONS = os.getenv("AWS_REGIONS", "").strip()

# Groq (OpenAI-compatible API)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

# IAM detector
# Access keys with no activity for this many days are flagged as unused.
# Lower this (e.g. to 0) temporarily to test the check against a freshly
# created key.
IAM_UNUSED_KEY_DAYS = int(os.getenv("IAM_UNUSED_KEY_DAYS", "90"))

# --- Web app auth ---
# Signs the session cookie. MUST be stable across restarts -- generating one at
# import would silently log every user out on every reload/redeploy.
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", str(14 * 24 * 3600)))  # 14 days
# Marks the session cookie Secure (HTTPS-only). Must stay false on plain-HTTP
# localhost: a Secure cookie over http:// is silently dropped, which presents as
# "login succeeds but I'm immediately logged out again".
SESSION_HTTPS_ONLY = _bool("SESSION_HTTPS_ONLY", "false")

# --- Scheduled scans ---
SCAN_SCHEDULE_ENABLED = _bool("SCAN_SCHEDULE_ENABLED", "false")
# Standard 5-field cron (minute hour day month day_of_week). Default: 02:00 daily.
SCAN_SCHEDULE_CRON = os.getenv("SCAN_SCHEDULE_CRON", "0 2 * * *")

# --- Email alerts (sent after a *scheduled* scan finds NEW findings) ---
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS = _bool("SMTP_USE_TLS", "true")
SMTP_FROM = os.getenv("SMTP_FROM", "")
# Comma-separated recipient list.
ALERT_TO = [a.strip() for a in os.getenv("ALERT_TO", "").split(",") if a.strip()]

# --- Remediation (write access!) ---
# Off by default on purpose: the scanner is read-only, and that guarantee is
# worth keeping unless the operator explicitly opts in. Turning this on requires
# granting the extra write permissions documented in the README.
REMEDIATION_ENABLED = _bool("REMEDIATION_ENABLED", "false")


def alerts_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM and ALERT_TO)

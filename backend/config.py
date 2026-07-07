import os

from dotenv import load_dotenv

load_dotenv()

# AWS — credentials themselves are picked up by boto3's default chain
# (env vars, ~/.aws/credentials, or an instance/role profile). We only
# need to know which named profile/region to use, if any.
AWS_PROFILE = os.getenv("AWS_PROFILE") or None
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Groq (OpenAI-compatible API)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

# IAM detector
# Access keys with no activity for this many days are flagged as unused.
# Lower this (e.g. to 0) temporarily to test the check against a freshly
# created key.
IAM_UNUSED_KEY_DAYS = int(os.getenv("IAM_UNUSED_KEY_DAYS", "90"))

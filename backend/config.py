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

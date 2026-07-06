from openai import OpenAI

from backend import config
from backend.models import Finding

_client = None

PROMPT_TEMPLATE = """You are a cloud security advisor helping a small startup team with \
limited AWS experience understand and fix a misconfiguration.

Finding:
- Resource: {resource_type} ({resource_id})
- Check: {check_type}
- Severity: {severity}
- Description: {description}
- Raw AWS detail: {detail}

Respond with two clearly labeled sections:
1. "Risk Explanation" — 2-4 plain-language sentences a non-security engineer can understand.
2. "Remediation" — concrete, numbered steps (include AWS CLI commands where useful) to fix it.
"""


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        if not config.GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY is not set. Add it to your .env file.")
        _client = OpenAI(api_key=config.GROQ_API_KEY, base_url=config.GROQ_BASE_URL)
    return _client


def explain_finding(finding: Finding) -> str:
    severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    prompt = PROMPT_TEMPLATE.format(
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        check_type=finding.check_type,
        severity=severity,
        description=finding.description,
        detail=finding.detail,
    )

    client = _get_client()
    completion = client.chat.completions.create(
        model=config.GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=600,
    )
    return completion.choices[0].message.content

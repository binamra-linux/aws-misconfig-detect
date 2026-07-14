"""
Shared test fixtures.

The autouse fixture below is load-bearing, not boilerplate: backend/config.py calls
load_dotenv() at import time and scanner.build_session() feeds AWS_PROFILE straight
into boto3.Session(). Without neutralising both, a developer who has a real profile
in their .env would have this suite authenticate against their LIVE AWS ACCOUNT
instead of moto. The fake credentials alone aren't enough -- the profile has to go too.
"""

import boto3
import pytest

from backend import config

AWS_REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_isolation(monkeypatch):
    """Force every test onto fake credentials and off any real named profile."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", AWS_REGION)

    monkeypatch.setattr(config, "AWS_PROFILE", None)
    monkeypatch.setattr(config, "AWS_REGION", AWS_REGION)
    monkeypatch.setattr(config, "AWS_REGIONS", "")


@pytest.fixture
def session():
    """A boto3 Session for use inside a @mock_aws block."""
    return boto3.Session(region_name=AWS_REGION)


def by_check(results, check_type):
    """All CheckResults of a given check_type."""
    return [r for r in results if r.check_type == check_type]


def one_check(results, check_type):
    """The single CheckResult of a given check_type -- fails loudly if not exactly one."""
    matches = by_check(results, check_type)
    assert len(matches) == 1, f"expected exactly one {check_type}, got {len(matches)}"
    return matches[0]

"""
IAM detector tests.

KNOWN moto LIMITATION: moto's get_account_summary() returns a hardcoded map with
AccountMFAEnabled=0 and AccountAccessKeysPresent=0, with no way to set them. So
only one branch of each root-account check is reachable here: ROOT_NO_MFA always
FAILs and ROOT_ACCESS_KEYS_PRESENT always PASSes under moto. The opposite branches
are verified against a real AWS account instead.
"""

from moto import mock_aws

from tests.conftest import by_check, one_check

from backend import config
from backend.detectors.iam_detector import scan_iam_checks
from backend.models import CheckStatus, Severity

ADMIN_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}"""

SCOPED_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]
}"""

STRONG_PASSWORD_POLICY = dict(
    MinimumPasswordLength=14,
    RequireSymbols=True,
    RequireNumbers=True,
    RequireUppercaseCharacters=True,
    RequireLowercaseCharacters=True,
)


@mock_aws
def test_wildcard_inline_policy_is_flagged(session):
    iam = session.client("iam")
    iam.create_user(UserName="admin-user")
    iam.put_user_policy(UserName="admin-user", PolicyName="god-mode", PolicyDocument=ADMIN_POLICY)

    results = scan_iam_checks(session)
    finding = one_check(
        [r for r in results if r.resource_id == "admin-user"], "IAM_OVERLY_PERMISSIVE_POLICY"
    )

    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.CRITICAL


@mock_aws
def test_scoped_inline_policy_passes(session):
    iam = session.client("iam")
    iam.create_user(UserName="scoped-user")
    iam.put_user_policy(UserName="scoped-user", PolicyName="narrow", PolicyDocument=SCOPED_POLICY)

    results = scan_iam_checks(session)
    finding = one_check(
        [r for r in results if r.resource_id == "scoped-user"], "IAM_OVERLY_PERMISSIVE_POLICY"
    )

    assert finding.status == CheckStatus.PASS


@mock_aws
def test_wildcard_policy_inherited_from_group_is_flagged(session):
    iam = session.client("iam")
    iam.create_user(UserName="member")
    iam.create_group(GroupName="admins")
    iam.put_group_policy(GroupName="admins", PolicyName="god-mode", PolicyDocument=ADMIN_POLICY)
    iam.add_user_to_group(GroupName="admins", UserName="member")

    results = scan_iam_checks(session)
    finding = one_check([r for r in results if r.resource_id == "member"], "IAM_OVERLY_PERMISSIVE_POLICY")

    # The user has no policy of their own -- the danger is inherited, and a check
    # that only looked at directly-attached policies would miss this entirely.
    assert finding.status == CheckStatus.FAIL
    assert finding.detail["policies"][0]["source"] == "inline_group_policy"
    assert finding.detail["policies"][0]["group"] == "admins"


@mock_aws
def test_console_user_without_mfa_is_flagged(session):
    iam = session.client("iam")
    iam.create_user(UserName="console-user")
    iam.create_login_profile(UserName="console-user", Password="Sup3rSecret!pw")

    results = scan_iam_checks(session)
    finding = one_check([r for r in results if r.resource_id == "console-user"], "IAM_NO_MFA")

    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.HIGH
    assert finding.detail["has_console_password"] is True


@mock_aws
def test_user_without_console_password_is_not_mfa_checked(session):
    iam = session.client("iam")
    iam.create_user(UserName="api-only")  # no login profile

    results = scan_iam_checks(session)

    # MFA is meaningless without console access. Emitting a check here would
    # inflate the "checks performed" denominator with an inapplicable question.
    assert not [r for r in by_check(results, "IAM_NO_MFA") if r.resource_id == "api-only"]


@mock_aws
def test_unused_access_key_is_flagged_when_threshold_is_zero(session, monkeypatch):
    # A freshly created key has never been used, so with a 0-day threshold it
    # should immediately qualify as unused.
    monkeypatch.setattr(config, "IAM_UNUSED_KEY_DAYS", 0)

    iam = session.client("iam")
    iam.create_user(UserName="key-user")
    key_id = iam.create_access_key(UserName="key-user")["AccessKey"]["AccessKeyId"]

    results = scan_iam_checks(session)
    # Access-key checks are keyed by "<user>/<key id>", since one user can have several.
    finding = one_check(
        [r for r in results if r.resource_id == f"key-user/{key_id}"], "IAM_UNUSED_ACCESS_KEY"
    )

    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.MEDIUM
    assert finding.detail["last_used_date"] is None  # never used


@mock_aws
def test_fresh_access_key_passes_under_default_threshold(session, monkeypatch):
    monkeypatch.setattr(config, "IAM_UNUSED_KEY_DAYS", 90)

    iam = session.client("iam")
    iam.create_user(UserName="key-user")
    key_id = iam.create_access_key(UserName="key-user")["AccessKey"]["AccessKeyId"]

    results = scan_iam_checks(session)
    finding = one_check(
        [r for r in results if r.resource_id == f"key-user/{key_id}"], "IAM_UNUSED_ACCESS_KEY"
    )

    # Brand new key, 90-day threshold -- not yet stale.
    assert finding.status == CheckStatus.PASS


@mock_aws
def test_missing_password_policy_is_high_severity(session):
    session.client("iam").create_user(UserName="anyone")

    results = scan_iam_checks(session)
    finding = one_check(results, "IAM_WEAK_PASSWORD_POLICY")

    # No policy at all means AWS's weak defaults apply -- worse than a merely
    # imperfect policy, hence HIGH rather than MEDIUM.
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.HIGH
    assert finding.detail["policy"] is None


@mock_aws
def test_strong_password_policy_passes(session):
    iam = session.client("iam")
    iam.update_account_password_policy(**STRONG_PASSWORD_POLICY)

    results = scan_iam_checks(session)

    assert one_check(results, "IAM_WEAK_PASSWORD_POLICY").status == CheckStatus.PASS


@mock_aws
def test_short_minimum_length_is_flagged(session):
    iam = session.client("iam")
    iam.update_account_password_policy(**{**STRONG_PASSWORD_POLICY, "MinimumPasswordLength": 8})

    results = scan_iam_checks(session)
    finding = one_check(results, "IAM_WEAK_PASSWORD_POLICY")

    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.MEDIUM
    assert any("minimum length is 8" in w for w in finding.detail["weaknesses"])


@mock_aws
def test_missing_character_class_is_flagged(session):
    iam = session.client("iam")
    iam.update_account_password_policy(**{**STRONG_PASSWORD_POLICY, "RequireSymbols": False})

    results = scan_iam_checks(session)
    finding = one_check(results, "IAM_WEAK_PASSWORD_POLICY")

    assert finding.status == CheckStatus.FAIL
    assert any("symbols" in w for w in finding.detail["weaknesses"])


@mock_aws
def test_root_checks_are_emitted(session):
    results = scan_iam_checks(session)

    # See module docstring: under moto these always land on the same branch, so we
    # assert the checks *run* rather than asserting a result we can't influence.
    assert one_check(results, "ROOT_NO_MFA").status == CheckStatus.FAIL
    assert one_check(results, "ROOT_ACCESS_KEYS_PRESENT").status == CheckStatus.PASS

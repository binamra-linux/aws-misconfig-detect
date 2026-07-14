import pytest

from backend.models import Finding, Severity
from backend.scoring import compute_security_score


def _finding(severity):
    return Finding(
        resource_id="r",
        resource_type="T",
        check_type="C",
        severity=severity,
        description="d",
    )


def test_no_findings_is_a_perfect_score():
    assert compute_security_score([]) == {"score": 100, "label": "Secure"}


@pytest.mark.parametrize(
    "severity,expected",
    [
        (Severity.CRITICAL, 75),
        (Severity.HIGH, 85),
        (Severity.MEDIUM, 92),
        (Severity.LOW, 97),
    ],
)
def test_single_finding_deducts_its_severity_weight(severity, expected):
    assert compute_security_score([_finding(severity)])["score"] == expected


def test_deductions_accumulate():
    findings = [_finding(Severity.CRITICAL), _finding(Severity.HIGH), _finding(Severity.LOW)]
    # 100 - 25 - 15 - 3
    assert compute_security_score(findings)["score"] == 57


def test_score_floors_at_zero_and_never_goes_negative():
    findings = [_finding(Severity.CRITICAL)] * 10  # would be -150 unclamped

    result = compute_security_score(findings)

    assert result["score"] == 0
    assert result["label"] == "At Risk"


@pytest.mark.parametrize(
    "findings,label",
    [
        ([], "Secure"),
        ([_finding(Severity.LOW)], "Secure"),  # 97
        ([_finding(Severity.CRITICAL)], "Needs Attention"),  # 75
        ([_finding(Severity.CRITICAL)] * 2, "At Risk"),  # 50
    ],
)
def test_labels_track_score_bands(findings, label):
    assert compute_security_score(findings)["label"] == label

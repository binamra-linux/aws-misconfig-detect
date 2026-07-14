"""
Scan-state tests: the single-scan lock and the new-findings diff.

These two are the highest-risk logic in the app. The lock is what stops a scheduled
scan from racing a manual one and corrupting shared state, and the diff is what
decides whether an alert email gets sent.
"""

import pytest

from backend import history, scan_service
from backend.models import CheckResult, CheckStatus, Severity


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Reset module state and redirect history to a temp file between tests."""
    monkeypatch.setattr(history, "_HISTORY_FILE", tmp_path / "history.json")
    monkeypatch.setattr(scan_service, "_current_checks", [])
    monkeypatch.setattr(scan_service, "_current_findings", [])
    monkeypatch.setattr(scan_service, "_scan_id", 0)
    monkeypatch.setattr(scan_service, "_scanned_at", None)
    monkeypatch.setattr(scan_service, "_scan_in_progress", False)
    monkeypatch.setattr(scan_service, "_scan_owner", None)


def _fail(check_type="C", resource_id="r", region="us-east-1"):
    return CheckResult(
        resource_id=resource_id,
        resource_type="T",
        check_type=check_type,
        status=CheckStatus.FAIL,
        severity=Severity.HIGH,
        description="d",
        region=region,
    )


def _pass(check_type="C", resource_id="r", region="us-east-1"):
    return CheckResult(
        resource_id=resource_id,
        resource_type="T",
        check_type=check_type,
        status=CheckStatus.PASS,
        description="d",
        region=region,
    )


# --- the lock ---

def test_scan_slot_can_be_claimed_once():
    assert scan_service.try_begin_scan("manual") is True
    # The whole point: a second claim must fail while the first is running.
    assert scan_service.try_begin_scan("scheduled") is False


def test_slot_is_reusable_after_end_scan():
    scan_service.try_begin_scan("manual")
    scan_service.end_scan()

    assert scan_service.try_begin_scan("scheduled") is True


def test_busy_message_names_the_scheduled_owner():
    scan_service.try_begin_scan("scheduled")

    # A user clicking Scan during a cron run should be told *why* it's busy, not
    # given a bare "already in progress" that looks like a bug.
    assert "scheduled" in scan_service.busy_message().lower()


def test_busy_message_for_a_manual_scan():
    scan_service.try_begin_scan("manual")

    assert "already in progress" in scan_service.busy_message().lower()


def test_owner_is_cleared_after_end_scan():
    scan_service.try_begin_scan("manual")
    assert scan_service.scan_owner() == "manual"

    scan_service.end_scan()
    assert scan_service.scan_owner() is None


# --- finalize + diff ---

def test_finalize_records_findings_and_ignores_passes():
    response, new = scan_service.finalize_scan([_fail(), _pass(check_type="OTHER")])

    assert len(response["findings"]) == 1
    assert response["scan_id"] == 1
    assert response["scanned_at"] is not None
    assert len(new) == 1


def test_first_scan_reports_everything_as_new():
    _, new = scan_service.finalize_scan([_fail("A", "r1"), _fail("B", "r2")])

    assert len(new) == 2


def test_unchanged_findings_are_not_reported_as_new():
    scan_service.finalize_scan([_fail("A", "r1")])

    _, new = scan_service.finalize_scan([_fail("A", "r1")])

    # This is what stops the nightly alert email from re-sending the same backlog
    # every single night until people filter it away.
    assert new == []


def test_only_the_genuinely_new_finding_is_reported():
    scan_service.finalize_scan([_fail("A", "r1")])

    _, new = scan_service.finalize_scan([_fail("A", "r1"), _fail("B", "r2")])

    assert len(new) == 1
    assert new[0].check_type == "B"


def test_a_finding_in_a_different_region_counts_as_new():
    scan_service.finalize_scan([_fail("A", "r1", region="us-east-1")])

    _, new = scan_service.finalize_scan(
        [_fail("A", "r1", region="us-east-1"), _fail("A", "r1", region="eu-west-1")]
    )

    # Same check, same resource id, different region -- a distinct problem.
    assert len(new) == 1
    assert new[0].region == "eu-west-1"


def test_a_resolved_finding_that_returns_is_new_again():
    scan_service.finalize_scan([_fail("A", "r1")])
    scan_service.finalize_scan([])  # fixed

    _, new = scan_service.finalize_scan([_fail("A", "r1")])  # regressed

    # A regression deserves an alert; treating it as "already known" would hide it.
    assert len(new) == 1


def test_scan_id_increments_per_scan():
    first, _ = scan_service.finalize_scan([])
    second, _ = scan_service.finalize_scan([])

    assert (first["scan_id"], second["scan_id"]) == (1, 2)


def test_findings_are_sorted_by_severity():
    low = CheckResult(
        resource_id="r-low",
        resource_type="T",
        check_type="LOW_C",
        status=CheckStatus.FAIL,
        severity=Severity.LOW,
        description="d",
    )
    critical = CheckResult(
        resource_id="r-crit",
        resource_type="T",
        check_type="CRIT_C",
        status=CheckStatus.FAIL,
        severity=Severity.CRITICAL,
        description="d",
    )

    response, _ = scan_service.finalize_scan([low, critical])

    assert [f["severity"] for f in response["findings"]] == ["CRITICAL", "LOW"]


# --- lookup + reset ---

def test_finding_lookup_rejects_a_stale_scan_id():
    scan_service.finalize_scan([_fail()])

    finding, error = scan_service.finding_at(scan_id=99, finding_id=0)

    assert finding is None and error == "stale"


def test_finding_lookup_rejects_an_out_of_range_index():
    response, _ = scan_service.finalize_scan([_fail()])

    finding, error = scan_service.finding_at(response["scan_id"], finding_id=5)

    assert finding is None and error == "not_found"


def test_reset_clears_findings_and_history():
    scan_service.finalize_scan([_fail()])
    assert history.load_history()

    scan_service.reset()

    response = scan_service.findings_response()
    assert response["findings"] == []
    assert response["scan_id"] == 0
    assert response["scanned_at"] is None
    assert history.load_history() == []

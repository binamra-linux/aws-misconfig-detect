from moto import mock_aws

from tests.conftest import AWS_REGION, one_check

from backend.detectors.cloudtrail_detector import scan_cloudtrail_checks
from backend.models import CheckStatus, Severity


def _trail(session, name, multi_region, log_validation=False):
    s3 = session.client("s3", region_name=AWS_REGION)
    bucket = f"{name}-logs"
    s3.create_bucket(Bucket=bucket)

    cloudtrail = session.client("cloudtrail", region_name=AWS_REGION)
    cloudtrail.create_trail(
        Name=name,
        S3BucketName=bucket,
        IsMultiRegionTrail=multi_region,
        EnableLogFileValidation=log_validation,
    )
    return cloudtrail


@mock_aws
def test_no_trail_at_all_is_flagged(session):
    results = scan_cloudtrail_checks(session)

    finding = one_check(results, "CLOUDTRAIL_NOT_ENABLED")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.HIGH
    assert finding.detail["trail_count"] == 0


@mock_aws
def test_multi_region_trail_that_is_logging_passes(session):
    cloudtrail = _trail(session, "main", multi_region=True)
    cloudtrail.start_logging(Name="main")

    results = scan_cloudtrail_checks(session)

    assert one_check(results, "CLOUDTRAIL_ENABLED").status == CheckStatus.PASS


@mock_aws
def test_trail_that_exists_but_is_not_logging_is_flagged(session):
    _trail(session, "idle", multi_region=True)  # created but never started

    results = scan_cloudtrail_checks(session)

    # A trail that exists but isn't logging provides no audit trail at all --
    # it must not be treated as compliant just because it's configured.
    assert one_check(results, "CLOUDTRAIL_NOT_ENABLED").status == CheckStatus.FAIL


@mock_aws
def test_single_region_trail_does_not_satisfy_the_check(session):
    cloudtrail = _trail(session, "regional", multi_region=False)
    cloudtrail.start_logging(Name="regional")

    results = scan_cloudtrail_checks(session)

    # CIS 3.1 requires multi-region coverage; a single-region trail leaves blind spots.
    assert one_check(results, "CLOUDTRAIL_NOT_ENABLED").status == CheckStatus.FAIL


@mock_aws
def test_log_file_validation_disabled_is_flagged(session):
    cloudtrail = _trail(session, "main", multi_region=True, log_validation=False)
    cloudtrail.start_logging(Name="main")

    results = scan_cloudtrail_checks(session)

    finding = one_check(results, "CLOUDTRAIL_LOG_VALIDATION_DISABLED")
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.LOW


@mock_aws
def test_log_file_validation_enabled_passes(session):
    cloudtrail = _trail(session, "main", multi_region=True, log_validation=True)
    cloudtrail.start_logging(Name="main")

    results = scan_cloudtrail_checks(session)

    assert one_check(results, "CLOUDTRAIL_LOG_VALIDATION_ENABLED").status == CheckStatus.PASS


@mock_aws
def test_log_validation_not_evaluated_without_an_active_trail(session):
    results = scan_cloudtrail_checks(session)

    # No active trail means the validation question doesn't apply. Recording a
    # check that couldn't be evaluated would inflate the "checks performed" count.
    assert not [r for r in results if "LOG_VALIDATION" in r.check_type]

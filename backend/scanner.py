"""
Scan orchestration: which detectors run, in which regions, in what order.

Services split into two groups, and getting this split right matters:

  GLOBAL (run exactly once, no region loop)
    - S3        : list_buckets is account-global; s3_detector already builds a
                  region-specific client per bucket for the regional sub-calls.
    - IAM       : global by nature.
    - CloudTrail: describe_trails() returns *shadow trails* -- replicas of
                  multi-region and organization trails from every other region.
                  One call therefore sees everything. Looping it per region
                  would report the same multi-region trail N times.

  REGIONAL (run once per region)
    - Security groups, EBS, RDS.

Regions are scanned in parallel because a serial pass over ~17 enabled regions
takes minutes. boto3's Session.client() is not thread-safe, so each worker
thread builds its *own* Session rather than sharing one.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, NamedTuple, Optional

import boto3

from backend import config
from backend.detectors.cloudtrail_detector import scan_cloudtrail_checks
from backend.detectors.ebs_detector import scan_ebs_checks
from backend.detectors.iam_detector import scan_iam_checks
from backend.detectors.rds_detector import scan_rds_checks
from backend.detectors.s3_detector import scan_s3_checks
from backend.detectors.sg_detector import scan_security_groups_checks
from backend.models import CheckResult, Finding

MAX_REGION_WORKERS = 8

GLOBAL_DETECTORS = [
    ("s3", "S3 buckets", scan_s3_checks),
    ("iam", "IAM", scan_iam_checks),
    ("cloudtrail", "CloudTrail", scan_cloudtrail_checks),
]

REGIONAL_DETECTORS = [
    ("sg", "Security groups", scan_security_groups_checks),
    ("ebs", "EBS volumes & snapshots", scan_ebs_checks),
    ("rds", "RDS instances & snapshots", scan_rds_checks),
]


class Stage(NamedTuple):
    """One unit of scan work, and the label the UI shows while it runs."""

    key: str
    label: str
    region: Optional[str]  # None for global detectors
    run: Callable[[boto3.Session], List[CheckResult]]


def build_session(region: Optional[str] = None) -> boto3.Session:
    region = region or config.AWS_REGION
    if config.AWS_PROFILE:
        return boto3.Session(profile_name=config.AWS_PROFILE, region_name=region)
    return boto3.Session(region_name=region)


def enabled_regions() -> List[str]:
    """The regions the regional detectors should scan, per config.AWS_REGIONS."""
    setting = config.AWS_REGIONS

    if not setting:
        return [config.AWS_REGION]

    if setting.lower() == "all":
        ec2 = build_session().client("ec2")
        # AllRegions=False (the default) returns only regions enabled/opted-in for
        # this account -- scanning opt-out regions would just raise auth errors.
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        return sorted(regions)

    return [r.strip() for r in setting.split(",") if r.strip()]


def plan_stages(regions: Optional[List[str]] = None) -> List[Stage]:
    """The full list of work units for one scan. Exposed so the API can stream
    real per-stage progress instead of guessing at it."""
    regions = regions if regions is not None else enabled_regions()
    multi = len(regions) > 1

    stages: List[Stage] = [
        Stage(key=key, label=f"Scanning {label}...", region=None, run=checks_fn)
        for key, label, checks_fn in GLOBAL_DETECTORS
    ]

    for region in regions:
        for key, label, checks_fn in REGIONAL_DETECTORS:
            stages.append(
                Stage(
                    key=f"{key}:{region}" if multi else key,
                    label=f"Scanning {label} in {region}..." if multi else f"Scanning {label}...",
                    region=region,
                    run=checks_fn,
                )
            )

    return stages


def _run_stage(stage: Stage) -> List[CheckResult]:
    # Own Session per call: Session.client() is not thread-safe, and these run
    # concurrently across regions.
    return stage.run(build_session(stage.region))


def run_full_scan() -> List[CheckResult]:
    """Every check performed, PASS and FAIL. Powers the Resources tab and scoring."""
    stages = plan_stages()

    global_stages = [s for s in stages if s.region is None]
    regional_stages = [s for s in stages if s.region is not None]

    results: List[CheckResult] = []
    for stage in global_stages:
        results.extend(_run_stage(stage))

    if regional_stages:
        workers = min(MAX_REGION_WORKERS, len(regional_stages))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for chunk in pool.map(_run_stage, regional_stages):
                results.extend(chunk)

    return results


def run_scan() -> List[Finding]:
    """Failures only -- what the Streamlit dashboard and /api/findings consume."""
    return [f for f in (r.to_finding() for r in run_full_scan()) if f is not None]


if __name__ == "__main__":
    import json

    results = run_scan()
    print(json.dumps([f.to_dict() for f in results], indent=2))

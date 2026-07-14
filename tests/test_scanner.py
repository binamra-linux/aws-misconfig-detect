from moto import mock_aws

from backend import config
from backend.scanner import GLOBAL_DETECTORS, REGIONAL_DETECTORS, enabled_regions, plan_stages


def _keys(stages):
    return [s.key for s in stages]


def test_unset_regions_falls_back_to_the_single_default_region(monkeypatch):
    monkeypatch.setattr(config, "AWS_REGIONS", "")
    monkeypatch.setattr(config, "AWS_REGION", "us-east-1")

    # Existing single-region users must not be silently switched to a slow
    # all-region scan just because the feature exists.
    assert enabled_regions() == ["us-east-1"]


def test_explicit_region_list_is_honoured(monkeypatch):
    monkeypatch.setattr(config, "AWS_REGIONS", "eu-west-1, ap-south-1")

    assert enabled_regions() == ["eu-west-1", "ap-south-1"]


@mock_aws
def test_all_enumerates_regions_from_aws(monkeypatch):
    monkeypatch.setattr(config, "AWS_REGIONS", "all")

    regions = enabled_regions()

    assert "us-east-1" in regions
    assert len(regions) > 1
    assert regions == sorted(regions)


def test_single_region_plan_has_one_stage_per_detector(monkeypatch):
    monkeypatch.setattr(config, "AWS_REGIONS", "")
    monkeypatch.setattr(config, "AWS_REGION", "us-east-1")

    stages = plan_stages()

    assert len(stages) == len(GLOBAL_DETECTORS) + len(REGIONAL_DETECTORS)
    # No region suffix when there's only one region -- the label would be noise.
    assert _keys(stages) == ["s3", "iam", "cloudtrail", "sg", "ebs", "rds"]


def test_global_detectors_run_once_regardless_of_region_count():
    stages = plan_stages(["us-east-1", "eu-west-1", "ap-south-1"])

    global_keys = [s.key for s in stages if s.region is None]

    # CloudTrail is the one that matters here: describe_trails() returns shadow
    # trails from every region, so scanning it per-region would report the same
    # multi-region trail three times.
    assert global_keys == ["s3", "iam", "cloudtrail"]
    assert len([s for s in stages if s.key == "cloudtrail"]) == 1


def test_regional_detectors_are_planned_once_per_region():
    regions = ["us-east-1", "eu-west-1"]

    stages = plan_stages(regions)
    regional = [s for s in stages if s.region is not None]

    assert len(regional) == len(REGIONAL_DETECTORS) * len(regions)
    for region in regions:
        assert {s.key for s in regional if s.region == region} == {
            f"sg:{region}",
            f"ebs:{region}",
            f"rds:{region}",
        }


def test_multi_region_stage_keys_are_unique():
    stages = plan_stages(["us-east-1", "eu-west-1", "ap-south-1"])

    keys = _keys(stages)

    # The frontend keys its progress segments by these -- duplicates would make
    # one completed stage light up several bars.
    assert len(keys) == len(set(keys))


def test_multi_region_labels_name_their_region():
    stages = plan_stages(["us-east-1", "eu-west-1"])

    sg_eu = next(s for s in stages if s.key == "sg:eu-west-1")

    assert "eu-west-1" in sg_eu.label

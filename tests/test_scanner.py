import pytest
from botocore.exceptions import ClientError
from conftest import launch_instance

from app import scanner
from app.checks import Check, Finding
from app.scanner import ScanStore, run_scan, scan_regions


def finding(severity, check="fake", resource="r"):
    return Finding(check=check, category="Security", severity=severity, resource=resource, title="t",
                   detail="d", recommendation="r")


def test_a_real_scan_over_a_mocked_account_finds_the_planted_problems(session):
    ec2 = session.client("ec2")
    group = ec2.create_security_group(GroupName="bastion", Description="x")
    ec2.authorize_security_group_ingress(GroupId=group["GroupId"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    session.client("s3").create_bucket(Bucket="open-bucket")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)
    launch_instance(session)

    result = run_scan(session, ["us-east-1"])
    checks = {f.check for f in result.findings}
    assert {"security_groups_open", "s3_public_access", "ebs_unattached", "ebs_unencrypted",
            "ec2_required_tags"} <= checks
    assert result.errors == []


def test_findings_are_sorted_most_severe_first(monkeypatch, session):
    fake = Check("fake", "Fake", "regional", lambda s, r: [finding("low"), finding("critical"), finding("high")])
    monkeypatch.setattr(scanner, "CHECKS", [fake])
    assert [f.severity for f in run_scan(session, ["us-east-1"]).findings] == ["critical", "high", "low"]


def test_a_failing_check_is_reported_and_the_others_still_run(monkeypatch, session):
    def denied(s, r):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, "ListBuckets")

    monkeypatch.setattr(scanner, "CHECKS", [Check("broken", "Broken check", "regional", denied),
                                            Check("fine", "Fine check", "regional", lambda s, r: [finding("high")])])
    result = run_scan(session, ["us-east-1"])
    assert len(result.findings) == 1
    assert len(result.errors) == 1 and result.errors[0]["check"] == "broken"
    assert "AccessDenied" in result.errors[0]["message"]


def test_a_bug_in_a_check_does_not_crash_the_scan(monkeypatch, session):
    monkeypatch.setattr(scanner, "CHECKS", [Check("buggy", "Buggy", "regional", lambda s, r: 1 / 0)])
    result = run_scan(session, ["us-east-1"])
    assert result.findings == [] and "ZeroDivisionError" in result.errors[0]["message"]


def test_regional_checks_run_per_region_and_global_checks_once(monkeypatch, session):
    calls = {"regional": [], "global": []}
    monkeypatch.setattr(scanner, "CHECKS", [
        Check("r", "R", "regional", lambda s, region: calls["regional"].append(region) or []),
        Check("g", "G", "global", lambda s, region: calls["global"].append(region) or []),
    ])
    result = run_scan(session, ["us-east-1", "eu-west-1"])
    assert calls == {"regional": ["us-east-1", "eu-west-1"], "global": ["us-east-1"]}
    assert result.checks_run == 3


def test_scan_regions_come_from_the_environment(monkeypatch):
    monkeypatch.delenv("SCAN_REGIONS", raising=False)
    assert scan_regions() == ["us-east-1"]
    monkeypatch.setenv("SCAN_REGIONS", "us-east-1, eu-west-1 ,")
    assert scan_regions() == ["us-east-1", "eu-west-1"]
    monkeypatch.setenv("SCAN_REGIONS", " , ")
    assert scan_regions() == ["us-east-1"]


def test_result_serialises_to_plain_data(session):
    result = run_scan(session, ["us-east-1"])
    data = result.to_dict()
    assert set(data) == {"started_at", "finished_at", "regions", "checks_run", "findings", "errors"}


def test_store_keeps_only_the_latest_scan(session):
    store = ScanStore()
    assert store.latest() is None
    first, second = run_scan(session, ["us-east-1"]), run_scan(session, ["us-east-1"])
    store.save(first)
    store.save(second)
    assert store.latest() is second


@pytest.mark.parametrize("service_name", ["ec2", "s3", "rds"])
def test_each_registered_check_has_a_title_and_scope(service_name):
    from app.checks import CHECKS
    assert CHECKS and all(c.title and c.scope in ("regional", "global") for c in CHECKS)

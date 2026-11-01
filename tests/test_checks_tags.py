from conftest import launch_instance

from app.checks.tags import ec2_required_tags, required_tags


def test_untagged_instance_misses_both_default_tags(session):
    instance = launch_instance(session)
    findings = ec2_required_tags(session, "us-east-1")
    assert len(findings) == 1 and findings[0].resource == instance
    assert "Name" in findings[0].detail and "Project" in findings[0].detail
    assert findings[0].category == "Governance"


def test_fully_tagged_instance_is_fine(session):
    launch_instance(session, {"Name": "web", "Project": "clouddesk"})
    assert ec2_required_tags(session, "us-east-1") == []


def test_an_empty_tag_value_counts_as_missing(session):
    launch_instance(session, {"Name": "web", "Project": ""})
    findings = ec2_required_tags(session, "us-east-1")
    assert len(findings) == 1 and "Project" in findings[0].detail and "Name" not in findings[0].detail


def test_terminated_instances_are_ignored(session):
    instance = launch_instance(session)
    session.client("ec2").terminate_instances(InstanceIds=[instance])
    assert ec2_required_tags(session, "us-east-1") == []


def test_required_tags_can_be_configured(session, monkeypatch):
    monkeypatch.setenv("REQUIRED_TAGS", "Owner, CostCenter")
    assert required_tags() == ["Owner", "CostCenter"]
    launch_instance(session, {"Name": "web", "Project": "x"})
    assert "Owner" in ec2_required_tags(session, "us-east-1")[0].detail

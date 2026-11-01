from conftest import launch_instance

from app.checks.ebs import ebs_unattached, ebs_unencrypted


def make_volume(session, size=8, encrypted=False):
    return session.client("ec2").create_volume(AvailabilityZone="us-east-1a", Size=size,
                                               Encrypted=encrypted)["VolumeId"]


def test_small_unattached_volume_is_low_cost(session):
    volume = make_volume(session, 8)
    findings = ebs_unattached(session, "us-east-1")
    assert len(findings) == 1 and findings[0].resource == volume
    assert findings[0].severity == "low" and findings[0].category == "Cost"


def test_large_unattached_volume_is_medium(session):
    make_volume(session, 150)
    assert ebs_unattached(session, "us-east-1")[0].severity == "medium"


def test_attached_volume_is_not_reported(session):
    volume = make_volume(session)
    instance = launch_instance(session)
    session.client("ec2").attach_volume(VolumeId=volume, InstanceId=instance, Device="/dev/sdh")
    assert ebs_unattached(session, "us-east-1") == []


def test_unencrypted_volume_is_reported_and_encrypted_is_not(session):
    plain = make_volume(session, encrypted=False)
    make_volume(session, encrypted=True)
    findings = ebs_unencrypted(session, "us-east-1")
    assert [f.resource for f in findings] == [plain] and findings[0].category == "Security"


def test_no_volumes_no_findings(session):
    assert ebs_unattached(session, "us-east-1") == [] and ebs_unencrypted(session, "us-east-1") == []

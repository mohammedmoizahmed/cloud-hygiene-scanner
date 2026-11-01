import pytest

from app.checks.security_groups import security_groups_open

WORLD = [{"CidrIp": "0.0.0.0/0"}]


def make_group(session, name, permissions):
    ec2 = session.client("ec2")
    group = ec2.create_security_group(GroupName=name, Description=name)
    ec2.authorize_security_group_ingress(GroupId=group["GroupId"], IpPermissions=permissions)
    return group["GroupId"]


def tcp(low, high, ranges=None, **extra):
    return {"IpProtocol": "tcp", "FromPort": low, "ToPort": high, "IpRanges": ranges or WORLD, **extra}


def scan(session):
    return security_groups_open(session, "us-east-1")


def test_ssh_open_to_the_world_is_a_high_finding(session):
    group_id = make_group(session, "bastion", [tcp(22, 22)])
    findings = scan(session)
    assert len(findings) == 1
    assert findings[0].severity == "high" and group_id in findings[0].resource and "SSH" in findings[0].title


@pytest.mark.parametrize("port", [80, 443, 8080])
def test_ordinary_web_ports_are_fine(session, port):
    make_group(session, "web", [tcp(port, port)])
    assert scan(session) == []


def test_ssh_from_a_private_range_is_fine(session):
    make_group(session, "internal", [tcp(22, 22, ranges=[{"CidrIp": "10.0.0.0/8"}])])
    assert scan(session) == []


def test_ipv6_open_to_the_world_is_caught(session):
    make_group(session, "v6", [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    findings = scan(session)
    assert len(findings) == 1 and "RDP" in findings[0].title


def test_all_traffic_is_critical(session):
    make_group(session, "open", [{"IpProtocol": "-1", "IpRanges": WORLD}])
    findings = scan(session)
    assert [f.severity for f in findings] == ["critical"] and "All traffic" in findings[0].title


def test_every_tcp_port_is_one_critical_finding_not_many(session):
    make_group(session, "allports", [tcp(0, 65535)])
    findings = scan(session)
    assert [f.severity for f in findings] == ["critical"]


def test_a_range_that_covers_a_database_port_is_caught(session):
    make_group(session, "range", [tcp(3300, 3310)])
    findings = scan(session)
    assert len(findings) == 1 and "MySQL" in findings[0].title


def test_udp_is_ignored(session):
    make_group(session, "dns", [{"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": WORLD}])
    assert scan(session) == []


def test_the_default_group_alone_is_clean(session):
    assert scan(session) == []


def test_findings_carry_what_a_report_needs(session):
    make_group(session, "bastion", [tcp(22, 22)])
    finding = scan(session)[0]
    assert finding.category == "Security" and finding.region == "us-east-1"
    assert finding.recommendation and finding.control_area == "Network security"

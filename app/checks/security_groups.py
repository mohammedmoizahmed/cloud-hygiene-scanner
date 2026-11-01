"""Network security: security groups that accept traffic from the whole internet."""
from .base import Finding, client, register

SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
CONTROL_AREA = "Network security"


def _open_to_world(permission: dict) -> bool:
    return any(r.get("CidrIp") == "0.0.0.0/0" for r in permission.get("IpRanges", [])) or any(
        r.get("CidrIpv6") == "::/0" for r in permission.get("Ipv6Ranges", [])
    )


@register("security_groups_open", "Security groups open to the internet")
def security_groups_open(session, region):
    ec2 = client(session, "ec2", region)
    findings: list[Finding] = []
    seen: set[tuple] = set()

    def add(group, key, severity, title, detail):
        if (group, key) in seen:
            return
        seen.add((group, key))
        findings.append(
            Finding(
                check="security_groups_open",
                category="Security",
                severity=severity,
                resource=group,
                title=title,
                detail=detail,
                recommendation="Restrict the source to the addresses or security groups that need access.",
                region=region,
                control_area=CONTROL_AREA,
            )
        )

    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            group = f"{sg['GroupId']} ({sg['GroupName']})"
            for permission in sg.get("IpPermissions", []):
                if not _open_to_world(permission):
                    continue
                protocol = permission.get("IpProtocol")
                if protocol == "-1":
                    add(group, "all", "critical", "All traffic is open to the internet",
                        "The group allows every protocol and port from anywhere.")
                    continue
                if protocol != "tcp":
                    continue
                low, high = permission.get("FromPort"), permission.get("ToPort")
                if low is None or high is None:
                    continue
                if low == 0 and high == 65535:
                    add(group, "all-tcp", "critical", "All TCP ports are open to the internet",
                        "The group allows ports 0-65535 from anywhere.")
                    continue
                for port, service in SENSITIVE_PORTS.items():
                    if low <= port <= high:
                        add(group, port, "high", f"{service} (port {port}) is open to the internet",
                            f"The group allows {service} from 0.0.0.0/0 or ::/0.")
    return findings

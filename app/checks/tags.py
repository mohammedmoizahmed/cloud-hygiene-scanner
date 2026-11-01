"""Governance: instances should carry the tags the organisation requires."""
import os

from .base import Finding, client, register


def required_tags() -> list[str]:
    raw = os.environ.get("REQUIRED_TAGS", "Name,Project")
    return [tag.strip() for tag in raw.split(",") if tag.strip()]


@register("ec2_required_tags", "EC2 instances missing required tags")
def ec2_required_tags(session, region):
    ec2 = client(session, "ec2", region)
    required = required_tags()
    findings = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] in ("terminated", "shutting-down"):
                    continue
                tags = {t["Key"]: t.get("Value", "") for t in instance.get("Tags", [])}
                missing = [tag for tag in required if not tags.get(tag)]
                if missing:
                    findings.append(Finding(
                        check="ec2_required_tags", category="Governance", severity="low",
                        resource=instance["InstanceId"],
                        title="Missing required tags",
                        detail="Missing or empty: " + ", ".join(missing) + ".",
                        recommendation="Add the tags so cost and ownership can be reported.",
                        region=region, control_area="Asset management and governance"))
    return findings

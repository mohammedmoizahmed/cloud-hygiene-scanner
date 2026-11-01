"""Cost and data protection: EBS volumes."""
from .base import Finding, client, register


@register("ebs_unattached", "Unattached EBS volumes")
def ebs_unattached(session, region):
    ec2 = client(session, "ec2", region)
    findings = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for volume in page["Volumes"]:
            size = volume["Size"]
            findings.append(Finding(
                check="ebs_unattached", category="Cost", severity="medium" if size >= 100 else "low",
                resource=volume["VolumeId"], title=f"Unattached volume ({size} GiB)",
                detail="The volume is not attached to any instance but is still billed.",
                recommendation="Take a snapshot if the data matters, then delete the volume.",
                region=region, control_area="Cost optimisation"))
    return findings


@register("ebs_unencrypted", "Unencrypted EBS volumes")
def ebs_unencrypted(session, region):
    ec2 = client(session, "ec2", region)
    findings = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for volume in page["Volumes"]:
            if volume.get("Encrypted"):
                continue
            findings.append(Finding(
                check="ebs_unencrypted", category="Security", severity="medium",
                resource=volume["VolumeId"], title="Volume is not encrypted",
                detail=f"The {volume['Size']} GiB volume is stored without encryption.",
                recommendation="Create an encrypted copy from a snapshot and switch to it. "
                               "Turn on EBS encryption by default for the region.",
                region=region, control_area="Data protection"))
    return findings

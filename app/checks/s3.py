"""Data protection: S3 buckets that are not blocked from becoming public."""
from botocore.exceptions import BotoCoreError, ClientError

from .base import Finding, client, register

FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
CONTROL_AREA = "Data protection and access control"
RECOMMENDATION = "Turn on all four Block Public Access settings unless the bucket must be public."


def _account_blocks_everything(session, region) -> bool:
    """If Block Public Access is fully on for the whole account, buckets need no setting of their own."""
    try:
        account = client(session, "sts", region).get_caller_identity()["Account"]
        config = client(session, "s3control", region).get_public_access_block(AccountId=account)
    except (ClientError, BotoCoreError):
        return False
    return all(config["PublicAccessBlockConfiguration"].get(flag) for flag in FLAGS)


@register("s3_public_access", "S3 Block Public Access", scope="global")
def s3_public_access(session, region):
    s3 = client(session, "s3", region)
    if _account_blocks_everything(session, region):
        return []
    findings: list[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            config = None
        if config is None:
            findings.append(Finding(
                check="s3_public_access", category="Security", severity="high", resource=name,
                title="No Block Public Access settings",
                detail="The bucket has no Block Public Access configuration, and neither does the account.",
                recommendation=RECOMMENDATION,
                control_area=CONTROL_AREA))
            continue
        off = [flag for flag in FLAGS if not config.get(flag)]
        if off:
            findings.append(Finding(
                check="s3_public_access", category="Security", severity="medium", resource=name,
                title="Block Public Access is only partly on",
                detail="These settings are off: " + ", ".join(off) + ".",
                recommendation=RECOMMENDATION,
                control_area=CONTROL_AREA))
    return findings

from app.checks.s3 import s3_public_access

FULL = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def scan(session):
    return s3_public_access(session, "us-east-1")


def test_no_buckets_no_findings(session):
    assert scan(session) == []


def test_bucket_without_any_setting_is_high(session):
    session.client("s3").create_bucket(Bucket="no-settings")
    findings = scan(session)
    assert len(findings) == 1 and findings[0].severity == "high" and findings[0].resource == "no-settings"


def test_partly_blocked_bucket_lists_what_is_off(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="partial")
    s3.put_public_access_block(Bucket="partial", PublicAccessBlockConfiguration={**FULL, "BlockPublicPolicy": False,
                                                                                  "IgnorePublicAcls": False})
    findings = scan(session)
    assert len(findings) == 1 and findings[0].severity == "medium"
    assert "BlockPublicPolicy" in findings[0].detail and "IgnorePublicAcls" in findings[0].detail


def test_fully_blocked_bucket_is_fine(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(Bucket="locked", PublicAccessBlockConfiguration=FULL)
    assert scan(session) == []


def test_account_level_block_covers_every_bucket(session):
    session.client("s3").create_bucket(Bucket="no-settings")
    account = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=FULL)
    assert scan(session) == []


def test_only_the_unprotected_bucket_is_reported(session):
    s3 = session.client("s3")
    for name in ("safe", "risky"):
        s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket="safe", PublicAccessBlockConfiguration=FULL)
    assert [f.resource for f in scan(session)] == ["risky"]

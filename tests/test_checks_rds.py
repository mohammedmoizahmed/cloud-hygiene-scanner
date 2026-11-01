from app.checks.rds import rds_posture


def make_db(session, name="db1", **overrides):
    options = dict(DBInstanceIdentifier=name, DBInstanceClass="db.t3.micro", Engine="mysql",
                   MasterUsername="admin", MasterUserPassword="a-long-password-1", AllocatedStorage=20)
    options.update(overrides)
    session.client("rds").create_db_instance(**options)


def titles(findings):
    return {f.title for f in findings}


def test_risky_database_gets_four_findings(session):
    make_db(session, PubliclyAccessible=True, StorageEncrypted=False, BackupRetentionPeriod=0, MultiAZ=False)
    findings = rds_posture(session, "us-east-1")
    assert titles(findings) == {"Database is publicly accessible", "Storage is not encrypted",
                                "Automated backups are off", "Database is not Multi-AZ"}
    assert {f.category for f in findings} == {"Security", "Resilience"}


def test_well_configured_database_is_clean(session):
    make_db(session, PubliclyAccessible=False, StorageEncrypted=True, BackupRetentionPeriod=7, MultiAZ=True)
    assert rds_posture(session, "us-east-1") == []


def test_only_the_weak_point_is_reported(session):
    make_db(session, PubliclyAccessible=False, StorageEncrypted=True, BackupRetentionPeriod=7, MultiAZ=False)
    assert titles(rds_posture(session, "us-east-1")) == {"Database is not Multi-AZ"}


def test_single_az_is_medium_and_backups_off_is_high(session):
    make_db(session, PubliclyAccessible=False, StorageEncrypted=True, BackupRetentionPeriod=0, MultiAZ=False)
    severity = {f.title: f.severity for f in rds_posture(session, "us-east-1")}
    assert severity["Automated backups are off"] == "high" and severity["Database is not Multi-AZ"] == "medium"


def test_no_databases_no_findings(session):
    assert rds_posture(session, "us-east-1") == []

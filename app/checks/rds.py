"""Security and resilience: database instances."""
from .base import Finding, client, register


@register("rds_posture", "RDS security and resilience")
def rds_posture(session, region):
    rds = client(session, "rds", region)
    findings = []

    def add(db_id, category, severity, title, detail, recommendation, area):
        findings.append(Finding(
            check="rds_posture", category=category, severity=severity, resource=db_id, title=title,
            detail=detail, recommendation=recommendation, region=region, control_area=area))

    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            db_id = db["DBInstanceIdentifier"]
            replica = bool(db.get("ReadReplicaSourceDBInstanceIdentifier"))
            if db.get("PubliclyAccessible"):
                add(db_id, "Security", "high", "Database is publicly accessible",
                    "The instance has a public endpoint.",
                    "Turn off public access and reach the database from inside the VPC.",
                    "Network security")
            if not db.get("StorageEncrypted"):
                add(db_id, "Security", "medium", "Storage is not encrypted",
                    "Data at rest on the instance is not encrypted.",
                    "Restore from an encrypted snapshot copy to a new instance.",
                    "Data protection")
            if not replica and db.get("BackupRetentionPeriod", 0) == 0:
                add(db_id, "Resilience", "high", "Automated backups are off",
                    "The backup retention period is 0 days.",
                    "Set a retention period of at least 7 days.",
                    "Backup and recovery")
            if not replica and not db.get("MultiAZ"):
                add(db_id, "Resilience", "medium", "Database is not Multi-AZ",
                    "A failure of the one Availability Zone would take the database down.",
                    "Enable Multi-AZ for databases that must stay available.",
                    "Availability and resilience")
    return findings

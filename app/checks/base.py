"""What a check returns, and how checks register themselves."""
from collections.abc import Callable
from dataclasses import asdict, dataclass

import boto3
from botocore.config import Config

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CATEGORIES = ["Security", "Cost", "Governance", "Resilience"]

_BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=20)


@dataclass(frozen=True)
class Finding:
    check: str
    category: str
    severity: str
    resource: str
    title: str
    detail: str
    recommendation: str
    region: str = "global"
    control_area: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Check:
    name: str
    title: str
    scope: str  # "regional" runs once per region, "global" runs once
    run: Callable[[boto3.Session, str], list[Finding]]


CHECKS: list[Check] = []


def register(name: str, title: str, scope: str = "regional"):
    """Decorator that adds a check function to the list the scanner runs."""

    def decorator(function):
        CHECKS.append(Check(name=name, title=title, scope=scope, run=function))
        return function

    return decorator


def client(session: boto3.Session, service: str, region: str):
    return session.client(service, region_name=region, config=_BOTO_CONFIG)

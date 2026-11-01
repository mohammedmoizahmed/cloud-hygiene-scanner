"""Runs every registered check, keeps going when one fails, and keeps the latest result."""
import logging
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

import boto3

from .checks import CHECKS, SEVERITIES, Finding

log = logging.getLogger("scanner")


def scan_regions() -> list[str]:
    raw = os.environ.get("SCAN_REGIONS", "us-east-1")
    return [r.strip() for r in raw.split(",") if r.strip()] or ["us-east-1"]


@dataclass
class ScanResult:
    started_at: str
    finished_at: str
    regions: list[str]
    checks_run: int
    findings: list[Finding]
    errors: list[dict]

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "regions": self.regions,
            "checks_run": self.checks_run,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def run_scan(session: boto3.Session | None = None, regions: list[str] | None = None) -> ScanResult:
    """Run all checks. A check that fails is reported as an error and does not stop the others."""
    session = session or boto3.Session()
    regions = regions or scan_regions()
    started = _now()
    findings: list[Finding] = []
    errors: list[dict] = []
    runs = 0
    for check in CHECKS:
        targets = regions[:1] if check.scope == "global" else regions
        for region in targets:
            runs += 1
            try:
                findings.extend(check.run(session, region))
            except Exception as exc:  # noqa: BLE001 - one broken check must not hide the rest
                log.exception("Check %s failed in %s", check.name, region)
                errors.append({"check": check.name, "title": check.title, "region": region,
                               "message": f"{type(exc).__name__}: {str(exc)[:200]}"})
    rank = {name: index for index, name in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (rank.get(f.severity, len(rank)), f.check, f.resource))
    return ScanResult(started_at=started, finished_at=_now(), regions=regions, checks_run=runs,
                      findings=findings, errors=errors)


class ScanStore:
    """Holds the most recent scan in memory."""

    def __init__(self):
        self._lock = threading.Lock()
        self._latest: ScanResult | None = None

    def latest(self) -> ScanResult | None:
        with self._lock:
            return self._latest

    def save(self, result: ScanResult) -> None:
        with self._lock:
            self._latest = result

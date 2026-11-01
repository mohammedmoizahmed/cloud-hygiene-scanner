"""Importing a module here is what registers its checks."""
from . import ebs, rds, s3, security_groups, tags  # noqa: F401
from .base import CATEGORIES, CHECKS, SEVERITIES, Check, Finding

__all__ = ["CATEGORIES", "CHECKS", "SEVERITIES", "Check", "Finding"]

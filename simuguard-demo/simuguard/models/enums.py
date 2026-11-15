"""Enumerations for SimuGuard AI security and simulation models."""

from enum import Enum
from typing import Any


class CaseInsensitiveEnum(str, Enum):
    """Base enum that allows case-insensitive string lookups."""

    @classmethod
    def _missing_(cls, value: Any) -> Any:
        if isinstance(value, str):
            upper_val = value.strip().upper()
            for member in cls:
                if member.value == upper_val:
                    return member
        return None


class Severity(CaseInsensitiveEnum):
    """Vulnerability and security gap severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DeploymentVerdict(CaseInsensitiveEnum):
    """Pre-flight deployment gate verdicts."""

    ALLOW = "ALLOW"
    WARN_MANUAL_REVIEW = "WARN_MANUAL_REVIEW"
    BLOCK_DEPLOYMENT = "BLOCK_DEPLOYMENT"


class AssetCriticality(CaseInsensitiveEnum):
    """Asset business and operational criticality levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class BlastTier(CaseInsensitiveEnum):
    """Blast radius propagation tier for an affected asset."""

    DIRECT = "DIRECT"
    CASCADING = "CASCADING"


class ImpactStatus(CaseInsensitiveEnum):
    """Explicit impact status of an asset or resource during simulation."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"

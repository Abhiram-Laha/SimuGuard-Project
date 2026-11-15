"""Security gap model representing an identified policy or posture violation."""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from simuguard.models.enums import Severity


class SecurityGap(BaseModel):
    """Represents a discrete security or compliance misconfiguration."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    severity: Severity = Field(
        ...,
        description="Standardized severity rating (CRITICAL, HIGH, MEDIUM, LOW)",
    )
    gap_title: str = Field(
        ...,
        min_length=3,
        description="Concise summary title of the security gap",
    )
    technical_impact: str = Field(
        ...,
        min_length=5,
        description="Technical blast radius and operational risk if deployed",
    )
    compliance_violation: str = Field(
        ...,
        min_length=3,
        description="Regulatory or benchmark control violated (e.g. CIS, NIST CSF, NIST SP 800-171)",
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Unique rule identifier that triggered this finding (e.g., PANOS-001, IAM-002)",
    )
    remediation_guidance: Optional[str] = Field(
        default=None,
        description="Prescriptive least-privilege remediation advice for this specific gap",
    )

    @field_validator("gap_title", "technical_impact", "compliance_violation")
    @classmethod
    def strip_and_validate_non_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty or whitespace only")
        return cleaned

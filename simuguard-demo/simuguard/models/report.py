"""Pre-flight simulation report model encapsulating the full pre-deployment analysis."""

from datetime import datetime, timezone
from typing import Any, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import DeploymentVerdict, Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.models.validation_check import ValidationCheck


class PreFlightSimulationReport(BaseModel):
    """Complete pre-deployment infrastructure simulation and blast-radius report."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    change_ticket_id: str = Field(
        ...,
        min_length=2,
        description="Identifier of the change request (e.g. PR-4082, CHG-9901)",
    )
    overall_risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated composite risk score bounded between 0 (safe) and 100 (maximum risk)",
    )
    deployment_verdict: DeploymentVerdict = Field(
        ...,
        description="Gate decision: ALLOW, WARN_MANUAL_REVIEW, or BLOCK_DEPLOYMENT",
    )
    executive_summary: str = Field(
        ...,
        min_length=10,
        description="Concise executive explanation of the simulation findings and key risks",
    )
    predicted_affected_assets: List[AffectedAsset] = Field(
        default_factory=list,
        description="List of infrastructure assets within the predicted blast radius",
    )
    identified_security_gaps: List[SecurityGap] = Field(
        default_factory=list,
        description="List of detected security, posture, and compliance gaps",
    )
    pre_implementation_validation_plan: List[ValidationCheck] = Field(
        default_factory=list,
        description="Ordered sequence of pre-implementation CLI verification checks",
    )
    safe_remediated_config: str = Field(
        ...,
        description="Prescribed least-privilege configuration patch (PAN-OS and/or IAM HCL)",
    )

    # Optional metadata with sensible defaults
    target_environment: str = Field(
        default="Enterprise Hybrid (PAN-OS / AWS)",
        description="Target deployment environment classification",
    )
    evaluated_file: Optional[str] = Field(
        default=None,
        description="Relative or absolute path to the evaluated Terraform file",
    )
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of report generation",
    )
    compliance_frameworks: List[str] = Field(
        default_factory=lambda: [
            "NIST CSF 2.0 (PR.AC, PR.PT)",
            "NIST SP 800-171 3.13.1",
            "CIS Palo Alto Firewall Benchmark v1.1.0",
        ],
        description="Compliance frameworks evaluated during pre-flight check",
    )

    @field_validator("change_ticket_id", "executive_summary")
    @classmethod
    def strip_and_validate_non_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty or whitespace only")
        return cleaned

    @field_validator("predicted_affected_assets", mode="before")
    @classmethod
    def coerce_affected_assets(cls, v: Any) -> Any:
        """Allow list of strings (legacy format) or dicts to be coerced into AffectedAsset."""
        if isinstance(v, list):
            coerced: List[Union[AffectedAsset, dict]] = []
            for item in v:
                if isinstance(item, str):
                    coerced.append(AffectedAsset.from_summary_string(item))
                else:
                    coerced.append(item)
            return coerced
        return v

    @property
    def affected_asset_summaries(self) -> List[str]:
        """Return formatted summary strings of all affected assets."""
        return [asset.to_display_string() for asset in self.predicted_affected_assets]

    @property
    def has_critical_gaps(self) -> bool:
        """Check if any security gap has CRITICAL severity."""
        return any(gap.severity == Severity.CRITICAL for gap in self.identified_security_gaps)

    @property
    def highest_severity(self) -> Optional[Severity]:
        """Return the highest severity among all identified security gaps."""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in order:
            if any(gap.severity == sev for gap in self.identified_security_gaps):
                return sev
        return None

    @property
    def is_blocked(self) -> bool:
        """Check if the deployment verdict is BLOCK_DEPLOYMENT."""
        return self.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT

    def to_legacy_dict(self) -> dict:
        """Export report in the exact format of the original simulation_output_artifact.json."""
        return {
            "change_ticket_id": self.change_ticket_id,
            "overall_risk_score": self.overall_risk_score,
            "deployment_verdict": self.deployment_verdict.value,
            "executive_summary": self.executive_summary,
            "predicted_affected_assets": self.affected_asset_summaries,
            "identified_security_gaps": [
                {
                    "severity": gap.severity.value,
                    "gap_title": gap.gap_title,
                    "technical_impact": gap.technical_impact,
                    "compliance_violation": gap.compliance_violation,
                }
                for gap in self.identified_security_gaps
            ],
            "pre_implementation_validation_plan": [
                {
                    "step_number": check.step_number,
                    "target_component": check.target_component,
                    "what_to_validate": check.what_to_validate,
                    "cli_command": check.cli_command,
                    "expected_pass_criteria": check.expected_pass_criteria,
                }
                for check in self.pre_implementation_validation_plan
            ],
            "safe_remediated_config": self.safe_remediated_config,
        }

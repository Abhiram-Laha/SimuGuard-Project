"""Shared fixtures for SimuGuard AI test suite."""

import pytest
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import (
    AssetCriticality,
    BlastTier,
    DeploymentVerdict,
    Severity,
)
from simuguard.models.report import PreFlightSimulationReport
from simuguard.models.security_gap import SecurityGap
from simuguard.models.validation_check import ValidationCheck


@pytest.fixture
def sample_security_gap() -> SecurityGap:
    """Return a valid critical security gap."""
    return SecurityGap(
        severity=Severity.CRITICAL,
        gap_title="Palo Alto App-ID & Threat Inspection Bypass",
        technical_impact="Allows arbitrary C2 tunneling over port 443 without malware inspection.",
        compliance_violation="CIS PAN-OS Benchmark v1.1.0 (Rule 4.1)",
        rule_id="PANOS-001",
        remediation_guidance="Enforce App-ID applications = ['ssl', 'web-browsing']",
    )


@pytest.fixture
def sample_affected_asset() -> AffectedAsset:
    """Return a valid affected asset."""
    return AffectedAsset(
        asset_id="pan-vm-core-firewall-01",
        asset_name="Palo Alto Core Perimeter Firewall",
        asset_type="NGFW_Palo_Alto",
        criticality=AssetCriticality.CRITICAL,
        blast_tier=BlastTier.DIRECT,
        impact_description="Security Rule 'Allow-Analytics-Outbound-Webhook' widened",
    )


@pytest.fixture
def sample_validation_check() -> ValidationCheck:
    """Return a valid validation check."""
    return ValidationCheck(
        step_number=1,
        target_component="Palo Alto PAN-OS Security Policy",
        what_to_validate="Verify that the rule enforces explicit App-ID ('ssl').",
        cli_command=(
            "test security-policy-match from Trust-DMZ to Untrust-Internet source 10.100.4.50 "
            "destination 52.84.120.5 protocol 6 port 443 application ssl"
        ),
        expected_pass_criteria="Rule matched MUST show application 'ssl' and action 'allow'.",
        command_type="PAN_OS_CLI",
    )


@pytest.fixture
def sample_valid_report(
    sample_security_gap: SecurityGap,
    sample_affected_asset: AffectedAsset,
    sample_validation_check: ValidationCheck,
) -> PreFlightSimulationReport:
    """Return a complete, valid simulation report."""
    return PreFlightSimulationReport(
        change_ticket_id="PR-4082 (Palo Alto Security Rule + IAM Attachment)",
        overall_risk_score=96,
        deployment_verdict=DeploymentVerdict.BLOCK_DEPLOYMENT,
        executive_summary=(
            "Proposed Palo Alto rule disables App-ID deep inspection by setting application to 'any' "
            "and destination to 'any', creating an uninspected egress tunnel while IAM changes grant "
            "access to the Restricted CUI Vault."
        ),
        predicted_affected_assets=[sample_affected_asset],
        identified_security_gaps=[sample_security_gap],
        pre_implementation_validation_plan=[sample_validation_check],
        safe_remediated_config="# Remediated PAN-OS configuration",
    )

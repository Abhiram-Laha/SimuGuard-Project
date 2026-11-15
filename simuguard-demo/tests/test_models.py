"""Unit tests for SimuGuard AI Pydantic v2 data models and enums."""

import pytest
from pydantic import ValidationError
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


class TestEnums:
    """Tests for standardized enum values and case-insensitive behavior."""

    @pytest.mark.parametrize(
        "val,expected",
        [
            ("CRITICAL", Severity.CRITICAL),
            ("critical", Severity.CRITICAL),
            ("High", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("LOW", Severity.LOW),
        ],
    )
    def test_severity_valid(self, val: str, expected: Severity):
        assert Severity(val) == expected

    def test_severity_invalid(self):
        with pytest.raises(ValueError):
            Severity("CATASTROPHIC")

    @pytest.mark.parametrize(
        "val,expected",
        [
            ("ALLOW", DeploymentVerdict.ALLOW),
            ("allow", DeploymentVerdict.ALLOW),
            ("WARN_MANUAL_REVIEW", DeploymentVerdict.WARN_MANUAL_REVIEW),
            ("warn_manual_review", DeploymentVerdict.WARN_MANUAL_REVIEW),
            ("BLOCK_DEPLOYMENT", DeploymentVerdict.BLOCK_DEPLOYMENT),
            ("block_deployment", DeploymentVerdict.BLOCK_DEPLOYMENT),
        ],
    )
    def test_deployment_verdict_valid(self, val: str, expected: DeploymentVerdict):
        assert DeploymentVerdict(val) == expected

    def test_deployment_verdict_invalid(self):
        with pytest.raises(ValueError):
            DeploymentVerdict("PROCEED_WITH_CAUTION")

    @pytest.mark.parametrize(
        "val,expected",
        [
            ("CRITICAL", AssetCriticality.CRITICAL),
            ("High", AssetCriticality.HIGH),
            ("MEDIUM", AssetCriticality.MEDIUM),
            ("low", AssetCriticality.LOW),
        ],
    )
    def test_asset_criticality_valid(self, val: str, expected: AssetCriticality):
        assert AssetCriticality(val) == expected

    def test_asset_criticality_invalid(self):
        with pytest.raises(ValueError):
            AssetCriticality("NON_EXISTENT")

    def test_blast_tier_valid(self):
        assert BlastTier("DIRECT") == BlastTier.DIRECT
        assert BlastTier("cascading") == BlastTier.CASCADING


class TestSecurityGap:
    """Tests for SecurityGap data model validation."""

    def test_valid_security_gap(self):
        gap = SecurityGap(
            severity=Severity.HIGH,
            gap_title="Destination Zone Wildcarding ('any')",
            technical_impact="Bypasses zero-trust egress filtering.",
            compliance_violation="NIST SP 800-171 3.13.1",
            rule_id="PANOS-003",
        )
        assert gap.severity == Severity.HIGH
        assert gap.gap_title == "Destination Zone Wildcarding ('any')"
        assert gap.rule_id == "PANOS-003"
        assert gap.remediation_guidance is None

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            SecurityGap(
                severity="SUPER_CRITICAL",  # type: ignore
                gap_title="Some Title",
                technical_impact="Some Impact",
                compliance_violation="Some Violation",
            )

    @pytest.mark.parametrize("blank_str", ["", "   ", "\t\n"])
    def test_empty_strings_rejected(self, blank_str: str):
        with pytest.raises(ValidationError):
            SecurityGap(
                severity=Severity.MEDIUM,
                gap_title=blank_str,
                technical_impact="Some Impact",
                compliance_violation="Some Violation",
            )


class TestAffectedAsset:
    """Tests for AffectedAsset model and blast-radius string parser."""

    def test_direct_instantiation(self):
        asset = AffectedAsset(
            asset_id="pan-vm-core-firewall-01",
            asset_name="Core Firewall",
            asset_type="NGFW_Palo_Alto",
            criticality=AssetCriticality.CRITICAL,
            blast_tier=BlastTier.DIRECT,
            impact_description="Policy modified",
        )
        assert asset.asset_id == "pan-vm-core-firewall-01"
        assert asset.blast_tier == BlastTier.DIRECT
        assert asset.to_display_string() == "pan-vm-core-firewall-01 (Direct: Policy modified)"

    def test_from_summary_string_direct(self):
        summary = "pan-vm-core-firewall-01 (Direct: Security Rule 'Allow-Analytics' widened)"
        asset = AffectedAsset.from_summary_string(summary)
        assert asset.asset_id == "pan-vm-core-firewall-01"
        assert asset.blast_tier == BlastTier.DIRECT
        assert asset.impact_description == "Security Rule 'Allow-Analytics' widened"

    def test_from_summary_string_cascading(self):
        summary = "s3-enterprise-cui-vault (Cascading: Exposed to cross-bucket read/exfiltration)"
        asset = AffectedAsset.from_summary_string(summary, default_criticality=AssetCriticality.CRITICAL)
        assert asset.asset_id == "s3-enterprise-cui-vault"
        assert asset.blast_tier == BlastTier.CASCADING
        assert asset.impact_description == "Exposed to cross-bucket read/exfiltration"
        assert asset.criticality == AssetCriticality.CRITICAL

    def test_from_summary_string_colon_fallback(self):
        summary = "subnet-trust-dmz: Egress opened to destination 'any'"
        asset = AffectedAsset.from_summary_string(summary)
        assert asset.asset_id == "subnet-trust-dmz"
        assert asset.blast_tier == BlastTier.DIRECT
        assert asset.impact_description == "Egress opened to destination 'any'"

    def test_from_summary_string_bare_fallback(self):
        summary = "bare-unformatted-asset-id"
        asset = AffectedAsset.from_summary_string(summary)
        assert asset.asset_id == "bare-unformatted-asset-id"
        assert asset.blast_tier == BlastTier.DIRECT


class TestValidationCheck:
    """Tests for ValidationCheck verification command model."""

    def test_valid_validation_check(self):
        check = ValidationCheck(
            step_number=1,
            target_component="Palo Alto PAN-OS Security Policy",
            what_to_validate="Verify App-ID enforcement",
            cli_command="test security-policy-match from Trust-DMZ to Untrust-Internet application ssl",
            expected_pass_criteria="Rule matched MUST show application 'ssl'",
        )
        assert check.step_number == 1
        assert check.command_type == "PAN_OS_CLI"

    def test_step_number_must_be_positive(self):
        with pytest.raises(ValidationError):
            ValidationCheck(
                step_number=0,  # Invalid: must be >= 1
                target_component="Palo Alto",
                what_to_validate="Verify something",
                cli_command="show running",
                expected_pass_criteria="pass",
            )

        with pytest.raises(ValidationError):
            ValidationCheck(
                step_number=-1,
                target_component="Palo Alto",
                what_to_validate="Verify something",
                cli_command="show running",
                expected_pass_criteria="pass",
            )


class TestPreFlightSimulationReport:
    """Tests for PreFlightSimulationReport root model."""

    def test_valid_report_instantiation(self, sample_valid_report: PreFlightSimulationReport):
        assert sample_valid_report.change_ticket_id.startswith("PR-4082")
        assert sample_valid_report.overall_risk_score == 96
        assert sample_valid_report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert len(sample_valid_report.predicted_affected_assets) == 1
        assert len(sample_valid_report.identified_security_gaps) == 1
        assert sample_valid_report.has_critical_gaps is True
        assert sample_valid_report.is_blocked is True
        assert sample_valid_report.highest_severity == Severity.CRITICAL

    @pytest.mark.parametrize("valid_score", [0, 50, 96, 100])
    def test_risk_score_valid_bounds(self, valid_score: int, sample_valid_report: PreFlightSimulationReport):
        sample_valid_report.overall_risk_score = valid_score
        assert sample_valid_report.overall_risk_score == valid_score

    @pytest.mark.parametrize("invalid_score", [-1, -50, 101, 200])
    def test_risk_score_invalid_bounds_rejected(self, invalid_score: int, sample_valid_report: PreFlightSimulationReport):
        # Test rejection on assignment (validate_assignment=True)
        with pytest.raises(ValidationError) as exc_info:
            sample_valid_report.overall_risk_score = invalid_score
        assert "overall_risk_score" in str(exc_info.value)

        # Test rejection on direct constructor
        payload = sample_valid_report.model_dump()
        payload["overall_risk_score"] = invalid_score
        with pytest.raises(ValidationError) as exc_info2:
            PreFlightSimulationReport(**payload)
        assert "overall_risk_score" in str(exc_info2.value)

    def test_legacy_string_assets_coercion(self):
        """Verify report automatically coerces legacy string lists into AffectedAsset objects."""
        raw_assets = [
            "pan-vm-core-firewall-01 (Direct: Security Rule widened)",
            "s3-enterprise-cui-vault (Cascading: Exposed to exfiltration)",
        ]
        report = PreFlightSimulationReport(
            change_ticket_id="PR-4082",
            overall_risk_score=85,
            deployment_verdict=DeploymentVerdict.BLOCK_DEPLOYMENT,
            executive_summary="Summary explanation of critical issues found.",
            predicted_affected_assets=raw_assets,  # type: ignore (testing coercion)
            safe_remediated_config="# Safe config",
        )
        assert len(report.predicted_affected_assets) == 2
        assert isinstance(report.predicted_affected_assets[0], AffectedAsset)
        assert report.predicted_affected_assets[0].asset_id == "pan-vm-core-firewall-01"
        assert report.predicted_affected_assets[0].blast_tier == BlastTier.DIRECT
        assert report.predicted_affected_assets[1].blast_tier == BlastTier.CASCADING

    def test_json_roundtrip_serialization(self, sample_valid_report: PreFlightSimulationReport):
        """Verify model_dump_json and model_validate_json preserve data integrity."""
        json_data = sample_valid_report.model_dump_json()
        restored = PreFlightSimulationReport.model_validate_json(json_data)
        assert restored.change_ticket_id == sample_valid_report.change_ticket_id
        assert restored.overall_risk_score == sample_valid_report.overall_risk_score
        assert restored.deployment_verdict == sample_valid_report.deployment_verdict
        assert len(restored.identified_security_gaps) == 1
        assert restored.identified_security_gaps[0].severity == Severity.CRITICAL

    def test_legacy_dict_export(self, sample_valid_report: PreFlightSimulationReport):
        """Verify to_legacy_dict produces schema matching original simulation_output_artifact.json."""
        legacy = sample_valid_report.to_legacy_dict()
        assert legacy["change_ticket_id"] == sample_valid_report.change_ticket_id
        assert legacy["overall_risk_score"] == 96
        assert legacy["deployment_verdict"] == "BLOCK_DEPLOYMENT"
        assert isinstance(legacy["predicted_affected_assets"], list)
        assert isinstance(legacy["predicted_affected_assets"][0], str)
        assert isinstance(legacy["identified_security_gaps"], list)
        assert legacy["identified_security_gaps"][0]["severity"] == "CRITICAL"
        assert isinstance(legacy["pre_implementation_validation_plan"], list)
        assert "safe_remediated_config" in legacy

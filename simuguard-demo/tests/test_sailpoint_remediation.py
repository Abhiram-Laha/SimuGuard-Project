"""Unit tests for SailPointRemediator (Stage 2)."""

import pytest
from simuguard.models.enums import Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.remediation.sailpoint_remediator import SailPointRemediator
from simuguard.rules.base_rule import RuleEvaluationContext


@pytest.fixture
def sailpoint_remediator():
    return SailPointRemediator()


class TestSailPointRemediator:
    """Test identity governance recommendations across SP-01 through SP-06 and SP-CORR."""

    def test_sp01_in_flight_access_assumption_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-01",
            severity=Severity.CRITICAL,
            gap_title="PENDING_IS_NOT_ACCESS Violation: Request 'req-101'",
            technical_impact="In-flight request assumed to confer access",
            compliance_violation="NIST SP 800-53 AC-2",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-01"
        assert "APPROVED" in rec.recommended_config_snippet
        assert "ZERO valid permissions" in rec.recommended_config_snippet

    def test_sp02_unprovisioned_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-02",
            severity=Severity.HIGH,
            gap_title="Unprovisioned Identity Grant: Event 'prov-201'",
            technical_impact="Provisioning unconfirmed on target",
            compliance_violation="NIST SP 800-53 AC-2",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-02"
        assert "VERIFIED_ON_SOURCE" in rec.recommended_config_snippet

    def test_sp03_sod_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-03",
            severity=Severity.CRITICAL,
            gap_title="Separation of Duties (SoD) Conflict: Dev + Prod Admin",
            technical_impact="Toxic role combination allows unilateral change",
            compliance_violation="SOX 404",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-03"
        assert "Revoke conflicting production administration role" in rec.recommended_config_snippet

    def test_sp04_contractor_privileged_access_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-04",
            severity=Severity.CRITICAL,
            gap_title="Contractor Privileged Profile Violation: 'c-101'",
            technical_impact="Vendor contractor assigned admin profile",
            compliance_violation="NIST SP 800-171 3.1.1",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-04"
        assert "sp-ap-dev-contractor" in rec.recommended_config_snippet

    def test_sp05_dormant_revoked_entitlement_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-05",
            severity=Severity.HIGH,
            gap_title="Outstanding Access-Removal Risk: Revoked Item 'ent-1'",
            technical_impact="Revoked entitlement not deprovisioned",
            compliance_violation="ISO 27001 A.9.2.6",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-05"
        assert "deprovisioning" in rec.recommended_config_snippet.lower()

    def test_sp06_privilege_creep_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-06",
            severity=Severity.MEDIUM,
            gap_title="Excessive Entitlement Accumulation: 6 entitlements",
            technical_impact="Accumulation exceeds departmental baseline",
            compliance_violation="NIST SP 800-53 AC-6",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-06"
        assert "micro-certification" in rec.recommended_config_snippet.lower()

    def test_sp_corr_unmapped_entity_remediation(self, sailpoint_remediator):
        gap = SecurityGap(
            rule_id="SP-01",
            severity=Severity.HIGH,
            gap_title="Unmapped Governance Entity: IAM Role 'role-test' has no correlated identity in SailPoint",
            technical_impact="Governance status is UNKNOWN",
            compliance_violation="NIST SP 800-53 AC-2",
        )
        ctx = RuleEvaluationContext()
        rec = sailpoint_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "SP-CORR"
        assert "correlation rule" in rec.recommended_config_snippet.lower()

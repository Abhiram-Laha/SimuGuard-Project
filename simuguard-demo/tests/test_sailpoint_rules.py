"""Unit tests for SimuGuard AI SailPoint identity governance rules (SP-01 through SP-06)."""

import pytest
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.models.enums import Severity
from simuguard.parsers.resource_models import AwsIamRolePolicyAttachmentResource
from simuguard.rules.base_rule import RuleEvaluationContext
from simuguard.rules.sailpoint_rules import (
    ContractorPrivilegedAccessRule,
    DormantRevokedEntitlementRule,
    InFlightAccessAssumptionRule,
    PrivilegeCreepRule,
    SeparationOfDutiesRule,
    UnprovisionedAccessRule,
)
from simuguard.rules.sod_matrix import SoDMatrixEvaluator


@pytest.fixture
def enterprise_sp_context():
    loader = EnterpriseDatasetLoader()
    sp_data = loader.load_sailpoint_governance()
    return RuleEvaluationContext(
        sailpoint_governance=sp_data,
        extra_metadata={"evaluate_all_identities": True},
    )


class TestSP01InFlightAccessAssumptionRule:
    """Test SP-01: Principle: PENDING_IS_NOT_ACCESS."""

    def test_pending_request_effective_access_flagged(self, enterprise_sp_context):
        rule = InFlightAccessAssumptionRule()
        # Synthetic context where a pending request is marked as effective
        sp_data = enterprise_sp_context.sailpoint_governance
        # sp-req-1003 is PENDING_APPROVAL. If we temporarily check direct reference:
        res = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="test_attachment",
            source_file="test.tf",
            role="role-developer",
            policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            raw_attributes={"request_reference": "sp-req-1003-pending-admin-access"},
        )

        findings = rule.evaluate([res], enterprise_sp_context)
        assert any(f.rule_id == "SP-01" for f in findings)
        assert any("PENDING_IS_NOT_ACCESS" in f.gap_title or "In-Flight" in f.gap_title for f in findings)

    def test_unmapped_iam_role_flags_unknown_governance_entity(self):
        rule = InFlightAccessAssumptionRule()
        loader = EnterpriseDatasetLoader()
        sp_data = loader.load_sailpoint_governance()
        ctx = RuleEvaluationContext(sailpoint_governance=sp_data)

        res = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="test_unmapped_role",
            source_file="test.tf",
            role="role-totally-unmapped-ghost-999",
            policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        findings = rule.evaluate([res], ctx)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Unmapped Governance Entity" in findings[0].gap_title


class TestSP02UnprovisionedAccessRule:
    """Test SP-02: Approved != Provisioned."""

    def test_unprovisioned_grant_flagged(self, enterprise_sp_context):
        rule = UnprovisionedAccessRule()
        findings = rule.evaluate([], enterprise_sp_context)
        # sp-prov-2004 is REQUESTED_NOT_PROVISIONED and sp-prov-2005 is FAILED
        assert len(findings) >= 2
        assert all(f.rule_id == "SP-02" for f in findings)
        assert any("sp-prov-2004" in f.gap_title for f in findings)
        assert any("sp-prov-2005" in f.gap_title for f in findings)


class TestSP03SeparationOfDutiesRule:
    """Test SP-03: Separation of Duties (SoD) Conflict Detection."""

    def test_sod_evaluator_developer_and_prod_admin_conflict(self):
        evaluator = SoDMatrixEvaluator()
        conflicts = evaluator.check_identity_sod(
            identity_id="sp-ident-test-user",
            assigned_role_ids={"sp-role-developer", "sp-role-cloud-administrator"},
            assigned_entitlement_ids=set(),
        )
        assert len(conflicts) == 1
        assert conflicts[0].conflict_def.conflict_id == "SOD-01"
        assert conflicts[0].conflict_def.severity == Severity.CRITICAL

    def test_sod_evaluator_finance_and_payment_admin_conflict(self):
        evaluator = SoDMatrixEvaluator()
        conflicts = evaluator.check_identity_sod(
            identity_id="sp-ident-finance-user",
            assigned_role_ids={"sp-role-finance-analyst", "sp-role-payment-security-custodian"},
            assigned_entitlement_ids=set(),
        )
        assert len(conflicts) == 1
        assert conflicts[0].conflict_def.conflict_id == "SOD-02"
        assert conflicts[0].conflict_def.severity == Severity.CRITICAL

    def test_sod_evaluator_clean_identity_no_conflict(self):
        evaluator = SoDMatrixEvaluator()
        conflicts = evaluator.check_identity_sod(
            identity_id="sp-ident-clean-dev",
            assigned_role_ids={"sp-role-developer"},
            assigned_entitlement_ids={"sp-ent-aws-dev-poweruser"},
        )
        assert len(conflicts) == 0


class TestSP04ContractorPrivilegedAccessRule:
    """Test SP-04: Contractor Privileged Access Violations."""

    def test_contractor_assigned_privileged_profile_flagged(self):
        rule = ContractorPrivilegedAccessRule()
        # Synthetic dataset with contractor holding prod admin
        synthetic_sp = {
            "identities": {
                "identities": [
                    {
                        "id": "sp-ident-contractor-bob",
                        "display_name": "Bob Contractor",
                        "employment_type": "CONTRACTOR",
                        "department": "Engineering (Contract)",
                    }
                ]
            },
            "relationships": {
                "relationships": [
                    {
                        "source": "sp-ident-contractor-bob",
                        "target": "sp-ap-aws-prod-admin",
                        "relationship": "ASSIGNED_ACCESS_PROFILE",
                    }
                ]
            },
        }
        ctx = RuleEvaluationContext(
            sailpoint_governance=synthetic_sp,
            extra_metadata={"evaluate_all_identities": True},
        )

        findings = rule.evaluate([], ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "SP-04"
        assert findings[0].severity == Severity.CRITICAL
        assert "Contractor Privileged Profile Violation" in findings[0].gap_title

    def test_employee_assigned_privileged_profile_not_flagged_by_sp04(self):
        rule = ContractorPrivilegedAccessRule()
        synthetic_sp = {
            "identities": {
                "identities": [
                    {
                        "id": "sp-ident-emp-alice",
                        "display_name": "Alice Employee",
                        "employment_type": "EMPLOYEE",
                        "department": "Infrastructure & Cloud DevOps",
                    }
                ]
            },
            "relationships": {
                "relationships": [
                    {
                        "source": "sp-ident-emp-alice",
                        "target": "sp-ap-aws-prod-admin",
                        "relationship": "ASSIGNED_ACCESS_PROFILE",
                    }
                ]
            },
        }
        ctx = RuleEvaluationContext(
            sailpoint_governance=synthetic_sp,
            extra_metadata={"evaluate_all_identities": True},
        )

        findings = rule.evaluate([], ctx)
        assert len(findings) == 0


class TestSP05DormantRevokedEntitlementRule:
    """Test SP-05: Outstanding Access-Removal Risk."""

    def test_revoked_dormant_entitlement_flagged(self, enterprise_sp_context):
        rule = DormantRevokedEntitlementRule()
        findings = rule.evaluate([], enterprise_sp_context)
        # sp-cert-2025-q4-dormant-revoked has decision REVOKED for liam-oconnor
        assert len(findings) >= 1
        assert any(f.rule_id == "SP-05" for f in findings)
        assert any("Outstanding Access-Removal Risk" in f.gap_title for f in findings)


class TestSP06PrivilegeCreepRule:
    """Test SP-06: Excessive Entitlement Accumulation."""

    def test_entitlements_exceeding_baseline_flagged(self):
        rule = PrivilegeCreepRule()
        synthetic_sp = {
            "identities": {
                "identities": [
                    {
                        "id": "sp-ident-overprivileged-user",
                        "display_name": "Greedy User",
                        "employment_type": "EMPLOYEE",
                        "department": "Finance & Treasury",  # baseline is 2
                    }
                ]
            },
            "relationships": {
                "relationships": [
                    {"source": "sp-ident-overprivileged-user", "target": "ent-1", "relationship": "HAS_ENTITLEMENT"},
                    {"source": "sp-ident-overprivileged-user", "target": "ent-2", "relationship": "HAS_ENTITLEMENT"},
                    {"source": "sp-ident-overprivileged-user", "target": "ent-3", "relationship": "HAS_ENTITLEMENT"},
                    {"source": "sp-ident-overprivileged-user", "target": "ent-4", "relationship": "HAS_ENTITLEMENT"},
                    {"source": "sp-ident-overprivileged-user", "target": "ent-5", "relationship": "HAS_ENTITLEMENT"},
                ]
            },
        }
        ctx = RuleEvaluationContext(
            sailpoint_governance=synthetic_sp,
            extra_metadata={"evaluate_all_identities": True},
        )

        findings = rule.evaluate([], ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "SP-06"
        assert findings[0].severity == Severity.MEDIUM
        assert "Privilege Creep Detected" in findings[0].gap_title


class TestSailPointCorrelationAndFallback:
    """Test AUDIT-02: Strict identity correlation and empty-resource fallback."""

    def test_empty_resources_returns_empty_by_default(self):
        from simuguard.rules.sailpoint_rules import correlate_identities_from_resources
        loader = EnterpriseDatasetLoader()
        sp_data = loader.load_sailpoint_governance()
        ctx = RuleEvaluationContext(sailpoint_governance=sp_data)

        correlated, unmapped = correlate_identities_from_resources([], sp_data, ctx)
        assert correlated == set()
        assert unmapped == []

        # Evaluate rules with default empty context -> zero findings
        rule = UnprovisionedAccessRule()
        findings = rule.evaluate([], ctx)
        assert len(findings) == 0

    def test_explicitly_requested_all_identity_evaluation(self):
        from simuguard.rules.sailpoint_rules import correlate_identities_from_resources
        loader = EnterpriseDatasetLoader()
        sp_data = loader.load_sailpoint_governance()
        ctx = RuleEvaluationContext(
            sailpoint_governance=sp_data,
            extra_metadata={"evaluate_all_identities": True},
        )

        correlated, unmapped = correlate_identities_from_resources([], sp_data, ctx)
        assert len(correlated) == 22
        assert "sp-ident-sarah-chen" in correlated
        assert "sp-ident-svc-analytics-ingest" in correlated
        assert unmapped == []

    def test_normal_resource_correlation(self):
        from simuguard.rules.sailpoint_rules import correlate_identities_from_resources
        loader = EnterpriseDatasetLoader()
        sp_data = loader.load_sailpoint_governance()
        ctx = RuleEvaluationContext(sailpoint_governance=sp_data)

        res = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="test_analytics_attachment",
            source_file="test.tf",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )

        correlated, unmapped = correlate_identities_from_resources([res], sp_data, ctx)
        assert correlated == {"sp-ident-svc-analytics-ingest"}
        assert unmapped == []

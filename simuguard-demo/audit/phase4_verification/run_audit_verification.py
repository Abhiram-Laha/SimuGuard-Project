"""Independent verification script for SimuGuard AI Phase 4 Security Analysis & Risk Engine."""

import json
import os
import sys
from pathlib import Path

# Add project root to path
repo_root = Path(__file__).parent.parent.parent.resolve()
sys.path.insert(0, str(repo_root))

from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.engine.risk_engine import (
    RiskEngine,
    SEVERITY_WEIGHTS,
    CRITICALITY_MULTIPLIERS,
)
from simuguard.graph.blast_radius import BlastRadiusAnalyzer, BlastRadiusResult, ImpactedNode
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import (
    AssetCriticality,
    BlastTier,
    DeploymentVerdict,
    ImpactStatus,
    Severity,
)
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
    ParsedTerraformFile,
)
from simuguard.reporters.json_reporter import JsonReporter
from simuguard.reporters.terminal_reporter import TerminalReporter
from simuguard.rules.base_rule import RuleEvaluationContext
from simuguard.rules.firewall_rules import (
    CrossZoneSegmentationRule,
    InsecureProtocolExposureRule,
    PanosAppIdBypassRule,
    RuleShadowingRule,
    ThreatProfileInspectionRule,
    UnrestrictedEgressRule,
)
from simuguard.rules.sailpoint_rules import (
    ContractorPrivilegedAccessRule,
    DormantRevokedEntitlementRule,
    InFlightAccessAssumptionRule,
    PrivilegeCreepRule,
    SeparationOfDutiesRule,
    UnprovisionedAccessRule,
)
from simuguard.rules.sod_matrix import SoDMatrixEvaluator


def run_verification():
    results = {
        "firewall_rules": {},
        "sailpoint_rules": {},
        "risk_engine": {},
        "verdict_precedence": {},
        "digital_twin": {},
        "terraform_parser": {},
        "sample_scenarios": {},
        "reporters": {},
    }

    loader = EnterpriseDatasetLoader()
    dt = loader.load_as_digital_twin_graph()
    sp_data = loader.load_sailpoint_governance()
    empty_ctx = RuleEvaluationContext()
    sp_all_ctx = RuleEvaluationContext(
        sailpoint_governance=sp_data,
        extra_metadata={"evaluate_all_identities": True},
    )

    # -------------------------------------------------------------
    # 1. Firewall Rules Verification
    # -------------------------------------------------------------
    # FW-01
    fw01 = PanosAppIdBypassRule()
    res_fw01_pos = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw01_pos",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(name="R1", applications=["any"], action="allow")]
    )
    res_fw01_neg = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw01_neg",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(name="R2", applications=["ssl", "web-browsing"], action="allow")]
    )
    gaps_fw01_pos = fw01.evaluate([res_fw01_pos], empty_ctx)
    gaps_fw01_neg = fw01.evaluate([res_fw01_neg], empty_ctx)
    results["firewall_rules"]["FW-01"] = {
        "status": "PASS" if len(gaps_fw01_pos) == 1 and len(gaps_fw01_neg) == 0 else "FAIL",
        "severity": gaps_fw01_pos[0].severity.value if gaps_fw01_pos else None,
        "positive_detected": len(gaps_fw01_pos) == 1,
        "negative_clean": len(gaps_fw01_neg) == 0,
    }

    # FW-02
    fw02 = UnrestrictedEgressRule()
    res_fw02_panos = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw02_panos",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(
            name="R_Egress",
            source_zones=["Trust-DMZ"],
            destination_zones=["Untrust-Internet"],
            destination_addresses=["any"],
            action="allow"
        )]
    )
    res_fw02_aws_all = AwsSecurityGroupRuleResource(
        resource_type="aws_security_group_rule",
        resource_name="all_ports",
        source_file="test.tf",
        rule_type="egress",
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"]
    )
    res_fw02_aws_scoped = AwsSecurityGroupRuleResource(
        resource_type="aws_security_group_rule",
        resource_name="https_only",
        source_file="test.tf",
        rule_type="egress",
        protocol="tcp",
        from_port=443,
        to_port=443,
        cidr_blocks=["0.0.0.0/0"]
    )
    gaps_fw02_panos = fw02.evaluate([res_fw02_panos], empty_ctx)
    gaps_fw02_aws_all = fw02.evaluate([res_fw02_aws_all], empty_ctx)
    gaps_fw02_aws_scoped = fw02.evaluate([res_fw02_aws_scoped], empty_ctx)
    results["firewall_rules"]["FW-02"] = {
        "status": "PASS" if (len(gaps_fw02_panos) == 1 and gaps_fw02_aws_all[0].severity == Severity.CRITICAL and gaps_fw02_aws_scoped[0].severity == Severity.HIGH) else "FAIL",
        "panos_severity": gaps_fw02_panos[0].severity.value if gaps_fw02_panos else None,
        "aws_all_ports_severity": gaps_fw02_aws_all[0].severity.value if gaps_fw02_aws_all else None,
        "aws_scoped_port_severity": gaps_fw02_aws_scoped[0].severity.value if gaps_fw02_aws_scoped else None,
    }

    # FW-03
    fw03 = ThreatProfileInspectionRule()
    res_fw03_protected = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw03_prot",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(
            name="R_Protected",
            source_zones=["Trust-DMZ"],
            destination_zones=["Untrust-Internet"],
            security_profile_group="none",
            action="allow"
        )]
    )
    res_fw03_exempt = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw03_exempt",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(
            name="R_Exempt",
            source_zones=["Management-Zone"],
            destination_zones=["Management-Zone"],
            security_profile_group=None,
            action="allow"
        )]
    )
    gaps_fw03_prot = fw03.evaluate([res_fw03_protected], empty_ctx)
    gaps_fw03_exempt = fw03.evaluate([res_fw03_exempt], empty_ctx)
    results["firewall_rules"]["FW-03"] = {
        "status": "PASS" if len(gaps_fw03_prot) == 1 and len(gaps_fw03_exempt) == 0 else "FAIL",
        "protected_zone_detected": len(gaps_fw03_prot) == 1,
        "exempt_zone_clean": len(gaps_fw03_exempt) == 0,
    }

    # FW-04
    fw04 = InsecureProtocolExposureRule()
    res_fw04_http = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw04_http",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(
            name="R_Cleartext",
            applications=["web-browsing"],
            services=["service-http"],
            action="allow"
        )]
    )
    res_fw04_ssl = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw04_ssl",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(
            name="R_SSL",
            applications=["ssl"],
            services=["service-https"],
            action="allow"
        )]
    )
    res_fw04_db = AwsSecurityGroupRuleResource(
        resource_type="aws_security_group_rule",
        resource_name="fw04_db",
        source_file="test.tf",
        rule_type="ingress",
        protocol="tcp",
        from_port=5432,
        to_port=5432,
        cidr_blocks=["0.0.0.0/0"]
    )
    gaps_fw04_http = fw04.evaluate([res_fw04_http], empty_ctx)
    gaps_fw04_ssl = fw04.evaluate([res_fw04_ssl], empty_ctx)
    gaps_fw04_db = fw04.evaluate([res_fw04_db], empty_ctx)
    results["firewall_rules"]["FW-04"] = {
        "status": "PASS" if (len(gaps_fw04_http) == 1 and len(gaps_fw04_ssl) == 0 and gaps_fw04_db[0].severity == Severity.CRITICAL) else "FAIL",
        "cleartext_flagged": len(gaps_fw04_http) == 1,
        "ssl_clean": len(gaps_fw04_ssl) == 0,
        "db_public_severity": gaps_fw04_db[0].severity.value if gaps_fw04_db else None,
    }

    # FW-05
    fw05 = RuleShadowingRule()
    res_fw05_shadow = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw05_shadow",
        source_file="test.tf",
        rules=[
            PanosSecurityPolicyRule(
                name="R_Broad",
                source_zones=["any"],
                source_addresses=["any"],
                destination_zones=["any"],
                destination_addresses=["any"],
                applications=["any"],
                services=["any"],
                action="allow"
            ),
            PanosSecurityPolicyRule(
                name="R_Narrow_Shadowed",
                source_zones=["Trust-DMZ"],
                source_addresses=["10.100.4.0/24"],
                destination_zones=["Untrust-Internet"],
                destination_addresses=["52.84.120.0/22"],
                applications=["ssl"],
                services=["service-https"],
                action="allow"
            )
        ]
    )
    gaps_fw05 = fw05.evaluate([res_fw05_shadow], empty_ctx)
    results["firewall_rules"]["FW-05"] = {
        "status": "PASS" if len(gaps_fw05) == 1 and "R_Narrow_Shadowed" in gaps_fw05[0].gap_title else "FAIL",
        "shadowing_detected": len(gaps_fw05) == 1,
    }

    # FW-06
    fw06 = CrossZoneSegmentationRule()
    res_fw06_prohibited = PanosSecurityPolicyResource(
        resource_type="panos_security_policy",
        resource_name="fw06_prohib",
        source_file="test.tf",
        rules=[PanosSecurityPolicyRule(
            name="Direct_To_Vault",
            source_zones=["Untrust-Internet"],
            destination_zones=["Restricted-Data-Vault"],
            action="allow"
        )]
    )
    gaps_fw06 = fw06.evaluate([res_fw06_prohibited], empty_ctx)
    results["firewall_rules"]["FW-06"] = {
        "status": "PASS" if len(gaps_fw06) == 1 and gaps_fw06[0].severity == Severity.CRITICAL else "FAIL",
        "cross_zone_severity": gaps_fw06[0].severity.value if gaps_fw06 else None,
    }

    # -------------------------------------------------------------
    # 2. SailPoint Rules Verification
    # -------------------------------------------------------------
    # SP-01
    sp01 = InFlightAccessAssumptionRule()
    res_sp01_unmapped = AwsIamRolePolicyAttachmentResource(
        resource_type="aws_iam_role_policy_attachment",
        resource_name="unmapped",
        source_file="test.tf",
        role="role-unmapped-ghost-role-999",
        policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess"
    )
    gaps_sp01_unmapped = sp01.evaluate([res_sp01_unmapped], RuleEvaluationContext(sailpoint_governance=sp_data))
    results["sailpoint_rules"]["SP-01 / SP-CORR"] = {
        "status": "PASS" if len(gaps_sp01_unmapped) == 1 and gaps_sp01_unmapped[0].severity == Severity.HIGH else "FAIL",
        "unmapped_role_flagged": len(gaps_sp01_unmapped) == 1,
    }

    # SP-02
    sp02 = UnprovisionedAccessRule()
    gaps_sp02 = sp02.evaluate([], sp_all_ctx)
    results["sailpoint_rules"]["SP-02"] = {
        "status": "PASS" if len(gaps_sp02) >= 2 else "FAIL",
        "unprovisioned_events_flagged": len(gaps_sp02),
    }

    # SP-03
    sod_eval = SoDMatrixEvaluator()
    sod_conflict = sod_eval.check_identity_sod("test_user", {"sp-role-developer", "sp-role-cloud-administrator"}, set())
    sod_clean = sod_eval.check_identity_sod("test_user", {"sp-role-developer"}, set())
    results["sailpoint_rules"]["SP-03 (SoD)"] = {
        "status": "PASS" if len(sod_conflict) == 1 and len(sod_clean) == 0 else "FAIL",
        "conflict_severity": sod_conflict[0].conflict_def.severity.value if sod_conflict else None,
    }

    # SP-04
    sp04 = ContractorPrivilegedAccessRule()
    synthetic_sp_contractor = {
        "identities": {"identities": [{"id": "contractor-1", "display_name": "Contractor", "employment_type": "CONTRACTOR"}]},
        "relationships": {"relationships": [{"source": "contractor-1", "target": "sp-ap-aws-prod-admin", "relationship": "ASSIGNED_ACCESS_PROFILE"}]}
    }
    gaps_sp04 = sp04.evaluate([], RuleEvaluationContext(sailpoint_governance=synthetic_sp_contractor, extra_metadata={"evaluate_all_identities": True}))
    results["sailpoint_rules"]["SP-04"] = {
        "status": "PASS" if len(gaps_sp04) == 1 and gaps_sp04[0].severity == Severity.CRITICAL else "FAIL",
        "contractor_severity": gaps_sp04[0].severity.value if gaps_sp04 else None,
    }

    # SP-05
    sp05 = DormantRevokedEntitlementRule()
    gaps_sp05 = sp05.evaluate([], sp_all_ctx)
    results["sailpoint_rules"]["SP-05"] = {
        "status": "PASS" if len(gaps_sp05) >= 1 and gaps_sp05[0].severity == Severity.HIGH else "FAIL",
        "revoked_flagged": len(gaps_sp05),
    }

    # SP-06
    sp06 = PrivilegeCreepRule()
    synthetic_sp_creep = {
        "identities": {"identities": [{"id": "creep-user", "display_name": "User", "department": "Finance & Treasury"}]},
        "relationships": {"relationships": [{"source": "creep-user", "target": f"ent-{i}", "relationship": "HAS_ENTITLEMENT"} for i in range(5)]}
    }
    gaps_sp06 = sp06.evaluate([], RuleEvaluationContext(sailpoint_governance=synthetic_sp_creep, extra_metadata={"evaluate_all_identities": True}))
    results["sailpoint_rules"]["SP-06"] = {
        "status": "PASS" if len(gaps_sp06) == 1 and gaps_sp06[0].severity == Severity.MEDIUM else "FAIL",
        "creep_flagged": len(gaps_sp06),
    }

    # -------------------------------------------------------------
    # 3. Risk Engine Mathematical Formula Verification
    # -------------------------------------------------------------
    engine = RiskEngine()
    # Scenario: 1 CRITICAL (weight 40), 1 HIGH (weight 25), Asset Criticality CRITICAL (1.5)
    # Direct = 2, Cascading = 5 -> beta = 1.0 + 0.05*2 + 0.02*5 = 1.20
    # Base = (40 + 25) * 1.5 = 65 * 1.5 = 97.5
    # Unrounded = 97.5 * 1.20 = 117.0 -> Final = 100
    mock_blast = BlastRadiusResult(
        direct_impacts=[
            ImpactedNode(node_id="d1", node_name="d1", node_type="T", criticality=AssetCriticality.CRITICAL, tier=BlastTier.DIRECT, impact_reason="direct impact reason", trigger_resource="t"),
            ImpactedNode(node_id="d2", node_name="d2", node_type="T", criticality=AssetCriticality.HIGH, tier=BlastTier.DIRECT, impact_reason="direct impact reason", trigger_resource="t"),
        ],
        cascading_impacts=[
            ImpactedNode(node_id=f"c{i}", node_name=f"c{i}", node_type="T", criticality=AssetCriticality.HIGH, tier=BlastTier.CASCADING, impact_reason="cascading impact reason", trigger_resource="t")
            for i in range(5)
        ]
    )
    test_gaps = [
        SecurityGap(rule_id="R1", severity=Severity.CRITICAL, gap_title="Crit Gap", technical_impact="impact", compliance_violation="comp"),
        SecurityGap(rule_id="R2", severity=Severity.HIGH, gap_title="High Gap", technical_impact="impact", compliance_violation="comp"),
    ]
    bd = engine.calculate_score(test_gaps, blast_radius=mock_blast)
    results["risk_engine"] = {
        "status": "PASS" if bd.raw_base_score == 97.5 and round(bd.blast_radius_multiplier, 2) == 1.20 and bd.final_risk_score == 100 and bd.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT else "FAIL",
        "raw_base_score": bd.raw_base_score,
        "blast_multiplier": bd.blast_multiplier if hasattr(bd, 'blast_multiplier') else bd.blast_radius_multiplier,
        "final_risk_score": bd.final_risk_score,
        "verdict": bd.verdict.value,
    }

    # -------------------------------------------------------------
    # 4. Verdict Precedence Verification
    # -------------------------------------------------------------
    # Case A: Low numerical score (3) with CRITICAL gap -> MUST BLOCK
    crit_only = [SecurityGap(rule_id="RC", severity=Severity.CRITICAL, gap_title="Crit", technical_impact="critical impact", compliance_violation="compliance")]
    bd_a = engine.calculate_score(crit_only, blast_radius=None)

    # Case B: Low numerical score (3) with HIGH gap -> MUST WARN
    high_only = [SecurityGap(rule_id="RH", severity=Severity.HIGH, gap_title="High", technical_impact="high impact", compliance_violation="compliance")]
    bd_b = engine.calculate_score(high_only, blast_radius=None)

    # Case C: Low score (3) with UNKNOWN impact -> MUST WARN
    low_only = [SecurityGap(rule_id="RL", severity=Severity.LOW, gap_title="Low", technical_impact="low impact", compliance_violation="compliance")]
    bd_c = engine.calculate_score(low_only, blast_radius=None, has_unknown_impact=True)

    # Case D: Clean with low score -> ALLOW
    bd_d = engine.calculate_score(low_only, blast_radius=None, has_unknown_impact=False)

    results["verdict_precedence"] = {
        "critical_forces_block": bd_a.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT,
        "high_forces_warn": bd_b.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW,
        "unknown_forces_warn": bd_c.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW,
        "clean_allows": bd_d.verdict == DeploymentVerdict.ALLOW,
        "status": "PASS" if (bd_a.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT and bd_b.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW and bd_c.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW and bd_d.verdict == DeploymentVerdict.ALLOW) else "FAIL",
    }

    # -------------------------------------------------------------
    # 5. Sample PR Scenarios Verification
    # -------------------------------------------------------------
    analyzer = SimuGuardAnalyzer(digital_twin=dt, dataset_loader=loader)
    rep_4082 = analyzer.analyze_file(str(repo_root / "changes" / "pr_4082_firewall_iam.tf"))
    rep_4083 = analyzer.analyze_file(str(repo_root / "changes" / "pr_4083_firewall_iam.tf"))
    rep_netflix = analyzer.analyze_file(str(repo_root / "changes" / "allow_netflix.tf"))

    results["sample_scenarios"]["PR-4082"] = {
        "verdict": rep_4082.deployment_verdict.value,
        "score": rep_4082.overall_risk_score,
        "affected_count": len(rep_4082.predicted_affected_assets),
        "cui_exposed": any("cui" in a.asset_id.lower() for a in rep_4082.predicted_affected_assets),
        "gaps": [g.gap_title for g in rep_4082.identified_security_gaps],
    }
    results["sample_scenarios"]["PR-4083"] = {
        "verdict": rep_4083.deployment_verdict.value,
        "score": rep_4083.overall_risk_score,
        "affected_count": len(rep_4083.predicted_affected_assets),
        "gaps": [g.gap_title for g in rep_4083.identified_security_gaps],
    }
    results["sample_scenarios"]["allow_netflix.tf"] = {
        "verdict": rep_netflix.deployment_verdict.value,
        "score": rep_netflix.overall_risk_score,
        "schema_error_flagged": any(g.rule_id == "SCHEMA-01" for g in rep_netflix.identified_security_gaps),
        "unmapped_flagged": any(g.rule_id == "TOPOLOGY-01" for g in rep_netflix.identified_security_gaps),
        "gaps": [g.gap_title for g in rep_netflix.identified_security_gaps],
    }

    # -------------------------------------------------------------
    # 6. Digital Twin & Blast Radius Traversal Verification
    # -------------------------------------------------------------
    broad_res = AwsIamRolePolicyAttachmentResource(
        resource_type="aws_iam_role_policy_attachment",
        resource_name="broad",
        source_file="test.tf",
        role="role-analytics-ingestion-svc",
        policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
    )
    scoped_res = AwsIamRolePolicyAttachmentResource(
        resource_type="aws_iam_role_policy_attachment",
        resource_name="scoped",
        source_file="test.tf",
        role="role-analytics-ingestion-svc",
        policy_arn="arn:aws:iam::111122223333:policy/S3TelemetryWriteOnly"
    )
    blast_analyzer = BlastRadiusAnalyzer(dt)
    res_broad = blast_analyzer.analyze_resources([broad_res])
    res_scoped = blast_analyzer.analyze_resources([scoped_res])

    unmapped_sg_res = AwsSecurityGroupRuleResource(
        resource_type="aws_security_group_rule",
        resource_name="unmapped_sg",
        source_file="test.tf",
        security_group_id="sg-nonexistent-unknown-9999"
    )
    res_unmapped = blast_analyzer.analyze_resources([unmapped_sg_res])

    has_unknowns = len(res_unmapped.unknown_impacts) > 0 or len(res_unmapped.unmapped_resources) > 0
    results["digital_twin"] = {
        "status": "PASS" if len(res_broad.cascading_impacts) > 0 and len(res_scoped.cascading_impacts) == 0 and has_unknowns else "FAIL",
        "total_active_nodes": dt.node_count,
        "total_active_edges": dt.edge_count,
        "broad_iam_cascading_count": len(res_broad.cascading_impacts),
        "scoped_iam_cascading_count": len(res_scoped.cascading_impacts),
        "unmapped_resource_triggers_unknown": has_unknowns,
        "unmapped_safe_nodes_is_zero": len(res_unmapped.not_affected_nodes) == 0,
    }

    # -------------------------------------------------------------
    # 7. Terraform Parser Verification
    # -------------------------------------------------------------
    parser = TerraformHclParser()
    p_4082 = parser.parse_file(str(repo_root / "changes" / "pr_4082_firewall_iam.tf"))
    p_4083 = parser.parse_file(str(repo_root / "changes" / "pr_4083_firewall_iam.tf"))
    p_netflix = parser.parse_file(str(repo_root / "changes" / "allow_netflix.tf"))

    results["terraform_parser"] = {
        "status": "PASS" if p_4082.is_valid_hcl and p_4083.is_valid_hcl and p_netflix.is_valid_hcl and len(p_netflix.provider_schema_errors) == 1 else "FAIL",
        "pr_4082_resources": [r.resource_type + "." + r.resource_name for r in p_4082.resources],
        "pr_4083_resources": [r.resource_type + "." + r.resource_name for r in p_4083.resources],
        "allow_netflix_resources": [r.resource_type + "." + r.resource_name for r in p_netflix.resources],
        "allow_netflix_schema_errors": [e.error_message for e in p_netflix.provider_schema_errors],
    }

    # -------------------------------------------------------------
    # 8. Reporters Verification
    # -------------------------------------------------------------
    import io
    json_str = JsonReporter.to_json(rep_4082)
    parsed_json = json.loads(json_str)
    required_keys = [
        "change_ticket_id",
        "overall_risk_score",
        "deployment_verdict",
        "executive_summary",
        "predicted_affected_assets",
        "identified_security_gaps",
        "pre_implementation_validation_plan",
        "safe_remediated_config",
    ]
    has_all_keys = all(k in parsed_json for k in required_keys)

    term_buf = io.StringIO()
    term_rep = TerminalReporter(out=term_buf, use_color=False)
    term_rep.render(rep_4082)
    term_output = term_buf.getvalue()
    renders_cleanly = "SIMUGUARD AI" in term_output and "PR-4082-FIREWALL-IAM" in term_output

    results["reporters"] = {
        "status": "PASS" if has_all_keys and renders_cleanly else "FAIL",
        "json_required_keys_present": has_all_keys,
        "terminal_renders_cleanly": renders_cleanly,
    }

    # Save summary
    out_dir = Path(__file__).parent.resolve()
    out_file = out_dir / "audit_summary.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run_verification()

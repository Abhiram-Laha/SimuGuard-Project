"""Integration tests for end-to-end before-and-after comparison on PR-4082 and PR-4083."""

import hashlib
from pathlib import Path
import pytest
from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.models.enums import DeploymentVerdict
from simuguard.remediation.comparison_engine import ComparisonEngine
from simuguard.remediation.config_generator import ConfigGenerator
from simuguard.remediation.models import FindingResolutionStatus
from simuguard.remediation.recommendation_engine import RecommendationEngine
from simuguard.remediation.validation_engine import ValidationEngine
from simuguard.reporters.remediation_reporter import RemediationReporter


@pytest.fixture
def repo_root():
    return Path(__file__).parent.parent.resolve()


@pytest.fixture
def pr_4082_path(repo_root):
    return str(repo_root / "changes" / "pr_4082_firewall_iam.tf")


@pytest.fixture
def pr_4083_path(repo_root):
    return str(repo_root / "changes" / "pr_4083_firewall_iam.tf")


class TestEndToEndBeforeAfterComparison:
    """End-to-end verification of remediation pipeline and differential comparison."""

    def test_pr_4082_end_to_end_remediation_and_comparison(self, pr_4082_path):
        # 1. Record original file hash to prove non-destructive preservation
        orig_bytes = Path(pr_4082_path).read_bytes()
        orig_sha = hashlib.sha256(orig_bytes).hexdigest()

        analyzer = SimuGuardAnalyzer()
        rec_engine = RecommendationEngine()
        config_gen = ConfigGenerator()
        val_engine = ValidationEngine(base_analyzer=analyzer)
        comp_engine = ComparisonEngine()

        # 2. Baseline Phase 4 Pre-flight Analysis
        pre_report = analyzer.analyze_file(pr_4082_path)
        assert pre_report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert pre_report.overall_risk_score == 100

        # 3. Generate Remediation Recommendations
        recs = rec_engine.generate_recommendations(
            security_gaps=pre_report.identified_security_gaps,
            resources=analyzer.parser.parse_file(pr_4082_path).resources,
        )
        assert len(recs) >= 2

        # 4. Generate Candidate Safe Configuration
        plan = config_gen.generate_candidate_hcl(
            original_file_path=pr_4082_path,
            recommendations=recs,
            change_ticket_id="PR-4082",
        )
        assert "arn:aws:iam::aws:policy/AmazonS3FullAccess" not in plan.synthesized_candidate_hcl
        assert "0.0.0.0/0" not in plan.synthesized_candidate_hcl
        assert "198.51.100.0/24" in plan.synthesized_candidate_hcl

        # 5. Closed-Loop Validation Re-Analysis
        post_report, overlay_result = val_engine.validate_candidate_plan(
            plan=plan,
            original_file_path=pr_4082_path,
        )
        assert post_report.deployment_verdict == DeploymentVerdict.ALLOW
        assert post_report.overall_risk_score == 0

        # 6. Differential Comparison
        comparison = comp_engine.compare_reports(
            pre_report=pre_report,
            post_report=post_report,
            overlay_result=overlay_result,
            change_ticket_id="PR-4082",
        )
        assert comparison.risk_score_delta == 100
        assert comparison.verdict_before == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert comparison.verdict_after == DeploymentVerdict.ALLOW
        assert comparison.resolved_count >= 1
        assert comparison.resolved_count + comparison.partially_resolved_count >= 2
        assert comparison.unresolved_count == 0
        assert comparison.regression_count == 0

        # 7. Verify Original File Unmodified
        after_sha = hashlib.sha256(Path(pr_4082_path).read_bytes()).hexdigest()
        assert orig_sha == after_sha

        # 8. Verify Reporter Rendering
        json_output = RemediationReporter.to_json(comparison)
        assert "PR-4082" in json_output
        assert "risk_score_delta" in json_output

        term_output = RemediationReporter.render_terminal(comparison, use_color=False)
        assert "SIMUGUARD AI — BEFORE-AND-AFTER VALIDATION REPORT" in term_output
        assert "PR-4082" in term_output
        assert "100" in term_output

    def test_pr_4083_end_to_end_remediation_and_comparison(self, pr_4083_path):
        orig_bytes = Path(pr_4083_path).read_bytes()
        orig_sha = hashlib.sha256(orig_bytes).hexdigest()

        analyzer = SimuGuardAnalyzer()
        rec_engine = RecommendationEngine()
        config_gen = ConfigGenerator()
        val_engine = ValidationEngine(base_analyzer=analyzer)
        comp_engine = ComparisonEngine()

        # Baseline
        pre_report = analyzer.analyze_file(pr_4083_path)
        assert pre_report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert pre_report.overall_risk_score == 100

        # Recommendations
        recs = rec_engine.generate_recommendations(
            security_gaps=pre_report.identified_security_gaps,
            resources=analyzer.parser.parse_file(pr_4083_path).resources,
        )
        assert len(recs) >= 3

        # Candidate generation
        plan = config_gen.generate_candidate_hcl(
            original_file_path=pr_4083_path,
            recommendations=recs,
            change_ticket_id="PR-4083",
        )
        assert 'applications          = ["any"]' not in plan.synthesized_candidate_hcl
        assert 'security_profile_group = "none"' not in plan.synthesized_candidate_hcl

        # Validation
        post_report, overlay_result = val_engine.validate_candidate_plan(
            plan=plan,
            original_file_path=pr_4083_path,
        )
        assert post_report.deployment_verdict == DeploymentVerdict.ALLOW
        assert post_report.overall_risk_score == 0

        # Comparison
        comparison = comp_engine.compare_reports(
            pre_report=pre_report,
            post_report=post_report,
            overlay_result=overlay_result,
            change_ticket_id="PR-4083",
        )
        assert comparison.risk_score_delta == 100
        assert comparison.verdict_after == DeploymentVerdict.ALLOW
        assert comparison.resolved_count >= 3
        assert comparison.regression_count == 0

        # Verify preservation
        after_sha = hashlib.sha256(Path(pr_4083_path).read_bytes()).hexdigest()
        assert orig_sha == after_sha

    def test_regression_detection_when_candidate_introduces_new_gap(self, pr_4082_path):
        analyzer = SimuGuardAnalyzer()
        comp_engine = ComparisonEngine()

        pre_report = analyzer.analyze_file(pr_4082_path)

        # Construct a synthetic post_report that has an unexpected new gap
        from simuguard.models.security_gap import SecurityGap
        from simuguard.models.enums import Severity
        post_report = pre_report.model_copy(deep=True)
        post_report.identified_security_gaps.append(
            SecurityGap(
                rule_id="FW-06",
                severity=Severity.CRITICAL,
                gap_title="Prohibited Cross-Zone Segmentation: Rule 'New-Vulnerability'",
                technical_impact="Direct untrusted access into core vault",
                compliance_violation="PCI-DSS Req 1.3",
            )
        )

        comparison = comp_engine.compare_reports(
            pre_report=pre_report,
            post_report=post_report,
            change_ticket_id="PR-REGRESSION",
        )
        assert comparison.regression_count >= 1
        reg_details = [d for d in comparison.finding_resolutions if d.resolution_status == FindingResolutionStatus.REGRESSION_INTRODUCED]
        assert len(reg_details) >= 1
        assert "New-Vulnerability" in reg_details[0].original_gap_title

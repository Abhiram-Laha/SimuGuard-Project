"""Integration tests for SimuGuard AI simulation engine and end-to-end PR analysis."""

import json
from pathlib import Path
import pytest
from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.models.enums import DeploymentVerdict
from simuguard.reporters.json_reporter import JsonReporter
from simuguard.reporters.terminal_reporter import TerminalReporter


@pytest.fixture
def analyzer():
    return SimuGuardAnalyzer()


@pytest.fixture
def repo_root():
    return Path(__file__).parent.parent.resolve()


class TestEndToEndSimulationPR4082:
    """Test full simulation on PR-4082 (AWS SG Egress + IAM S3FullAccess)."""

    def test_pr_4082_simulation_verdict_and_cui_exposure(self, analyzer, repo_root):
        pr_file = repo_root / "changes" / "pr_4082_firewall_iam.tf"
        report = analyzer.analyze_file(str(pr_file))

        assert report.change_ticket_id == "PR-4082-FIREWALL-IAM"
        assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert report.overall_risk_score >= 70

        # Verify affected assets include CUI vault
        asset_ids = {a.asset_id for a in report.predicted_affected_assets}
        assert "s3-enterprise-cui-vault" in asset_ids
        assert "DATA-01-CUI-FINANCIAL-VAULT" in asset_ids
        assert "eks-analytics-worker-pool" in asset_ids

        # Verify security gaps
        gap_titles = [g.gap_title for g in report.identified_security_gaps]
        assert any("Unrestricted AWS Security Group Egress" in t for t in gap_titles)
        assert any("Cloud Privilege Escalation" in t for t in gap_titles)


class TestEndToEndSimulationPR4083:
    """Test full simulation on PR-4083 (Palo Alto App-ID bypass + S3FullAccess)."""

    def test_pr_4083_simulation_verdict_and_app_id_bypass(self, analyzer, repo_root):
        pr_file = repo_root / "changes" / "pr_4083_firewall_iam.tf"
        report = analyzer.analyze_file(str(pr_file))

        assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert report.overall_risk_score >= 70

        # Verify App-ID bypass gap is flagged
        gap_rule_ids = {g.rule_id for g in report.identified_security_gaps}
        assert "FW-01" in gap_rule_ids  # App-ID bypass
        assert "FW-02" in gap_rule_ids  # Unrestricted egress
        assert "FW-03" in gap_rule_ids  # Missing threat profile
        assert "IAM-01" in gap_rule_ids  # Cloud privilege escalation


class TestEndToEndSimulationAllowNetflix:
    """Test full simulation on allow_netflix.tf (AWS provider schema error + unmapped SG)."""

    def test_allow_netflix_reports_schema_error_and_warns(self, analyzer, repo_root):
        pr_file = repo_root / "changes" / "allow_netflix.tf"
        report = analyzer.analyze_file(str(pr_file))

        # Must NOT be ALLOW due to schema error and unmapped SG
        assert report.deployment_verdict == DeploymentVerdict.WARN_MANUAL_REVIEW
        assert report.overall_risk_score < 40  # Numerical score is below 40, but verdict is WARN

        # Verify schema error is captured separately
        gap_rule_ids = {g.rule_id for g in report.identified_security_gaps}
        assert "SCHEMA-01" in gap_rule_ids
        assert "TOPOLOGY-01" in gap_rule_ids


class TestReportersIntegration:
    """Test TerminalReporter and JsonReporter."""

    def test_json_reporter_export_and_valid_json(self, analyzer, repo_root, tmp_path):
        pr_file = repo_root / "changes" / "pr_4082_firewall_iam.tf"
        report = analyzer.analyze_file(str(pr_file))

        out_json_file = tmp_path / "report.json"
        saved = JsonReporter.export_to_file(report, out_json_file)
        assert saved.is_file()

        raw = json.loads(saved.read_text(encoding="utf-8"))
        assert raw["change_ticket_id"] == "PR-4082-FIREWALL-IAM"
        assert raw["overall_risk_score"] == report.overall_risk_score
        assert raw["deployment_verdict"] == "BLOCK_DEPLOYMENT"

    def test_terminal_reporter_renders_without_exceptions(self, analyzer, repo_root):
        import io
        pr_file = repo_root / "changes" / "pr_4082_firewall_iam.tf"
        report = analyzer.analyze_file(str(pr_file))

        buf = io.StringIO()
        reporter = TerminalReporter(out=buf, use_color=False)
        reporter.render(report)
        output = buf.getvalue()

        assert "SIMUGUARD AI" in output
        assert "PR-4082-FIREWALL-IAM" in output
        assert "BLOCK_DEPLOYMENT" in output
        assert "PREDICTED INFRASTRUCTURE BLAST RADIUS" in output
        assert "PRE-IMPLEMENTATION VALIDATION PLAYBOOK" in output

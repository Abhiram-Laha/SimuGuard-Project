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


class TestHclSyntaxErrorMapping:
    """Test AUDIT-01: Explicit mapping of HCL syntax errors to SYNTAX-01."""

    def test_malformed_hcl_generates_syntax01_critical_gap_and_blocks(self, analyzer, tmp_path):
        malformed_file = tmp_path / "broken_syntax.tf"
        malformed_file.write_text(
            'resource "panos_security_policy" "broken" {\n  rule {\n    name = "unclosed\n',
            encoding="utf-8",
        )

        report = analyzer.analyze_file(str(malformed_file))

        # Check verdict cannot be ALLOW; MUST be BLOCK_DEPLOYMENT due to CRITICAL syntax error
        assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert report.deployment_verdict != DeploymentVerdict.ALLOW

        # Verify SYNTAX-01 finding details
        syntax_gaps = [g for g in report.identified_security_gaps if g.rule_id == "SYNTAX-01"]
        assert len(syntax_gaps) >= 1
        gap = syntax_gaps[0]
        assert gap.severity.value == "CRITICAL"
        assert "broken_syntax.tf" in gap.gap_title
        assert "parsing failed" in gap.technical_impact.lower()

        # Verify JSON report includes SYNTAX-01
        json_output = JsonReporter.to_json(report)
        assert "SYNTAX-01" in json_output
        assert "broken_syntax.tf" in json_output

        # Verify Terminal report renders SYNTAX-01 finding
        import io
        buf = io.StringIO()
        reporter = TerminalReporter(out=buf, use_color=False)
        reporter.render(report)
        term_text = buf.getvalue()
        assert "[SYNTAX-01]" in term_text
        assert "HCL Syntax Error" in term_text


class TestEmptyResourcesNoSailPointLeakage:
    """Test AUDIT-02: Empty resource sets do not trigger unrelated SailPoint findings."""

    def test_empty_comment_file_produces_no_sailpoint_findings(self, analyzer, tmp_path):
        empty_tf = tmp_path / "empty_comments.tf"
        empty_tf.write_text(
            "# Ticket: PR-9999\n# Only comments, zero infrastructure resources.\n",
            encoding="utf-8",
        )

        report = analyzer.analyze_file(str(empty_tf))

        # Must not contain any SailPoint governance findings
        sp_gaps = [g for g in report.identified_security_gaps if (g.rule_id or "").startswith("SP-")]
        assert len(sp_gaps) == 0

        # Unrelated entities must not be leaked
        all_titles = " ".join(g.gap_title for g in report.identified_security_gaps)
        assert "sp-prov-2004" not in all_titles
        assert "liam-oconnor" not in all_titles
        assert "vikram-sharma" not in all_titles

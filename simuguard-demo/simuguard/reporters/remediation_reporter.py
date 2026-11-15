"""Remediation and before-and-after comparison reporter.

Formats BeforeAfterComparisonReport into:
- Structured JSON export
- Rich console / terminal comparison views
"""

import io
import json
import sys
from typing import Optional, TextIO
from simuguard.remediation.models import BeforeAfterComparisonReport, FindingResolutionStatus


class RemediationReporter:
    """Renders structured before-and-after remediation reports for NetOps and SecOps."""

    @staticmethod
    def to_json(report: BeforeAfterComparisonReport, indent: int = 2) -> str:
        """Export comparison report as serialized JSON."""
        return report.model_dump_json(indent=indent)

    @classmethod
    def render_terminal(
        cls,
        report: BeforeAfterComparisonReport,
        out: Optional[TextIO] = None,
        use_color: bool = True,
    ) -> str:
        """Render human-readable before-and-after comparison table to terminal or buffer."""
        buffer = io.StringIO()
        target = out or buffer

        c_reset = "\033[0m" if use_color else ""
        c_bold = "\033[1m" if use_color else ""
        c_red = "\033[31m" if use_color else ""
        c_green = "\033[32m" if use_color else ""
        c_yellow = "\033[33m" if use_color else ""
        c_cyan = "\033[36m" if use_color else ""

        target.write("=" * 100 + "\n")
        target.write(f"{c_bold}                        SIMUGUARD AI — BEFORE-AND-AFTER VALIDATION REPORT{c_reset}\n")
        target.write("=" * 100 + "\n")
        target.write(f"Change Ticket ID : {report.change_ticket_id}\n")
        target.write(f"Pre-Verdict      : {report.verdict_before.value} (Score: {report.risk_score_before}/100)\n")
        target.write(f"Post-Verdict     : {c_green if report.verdict_after.value == 'ALLOW' else c_yellow}{report.verdict_after.value}{c_reset} (Score: {report.risk_score_after}/100)\n")
        target.write(f"Net Risk Delta   : {c_green if report.risk_score_delta > 0 else c_red}{report.risk_score_delta:+d} Points{c_reset}\n")
        target.write("-" * 100 + "\n\n")

        # 1. Metric Summary Table
        target.write(f"{c_bold}1. METRIC COMPARISON SUMMARY{c_reset}\n")
        target.write(f"   {'Metric':<32} {'Pre-Remediation':<20} {'Post-Remediation':<20} {'Improvement Delta'}\n")
        target.write(f"   {'-'*32} {'-'*20} {'-'*20} {'-'*18}\n")
        target.write(f"   {'Composite Risk Score':<32} {report.risk_score_before:<20} {report.risk_score_after:<20} {report.risk_score_delta:+d} points\n")
        target.write(f"   {'Deployment Gate Verdict':<32} {report.verdict_before.value:<20} {report.verdict_after.value:<20} {'GATE PASSED' if report.verdict_after.value == 'ALLOW' else 'PENDING'}\n")
        target.write(f"   {'Direct Blast Impact Assets':<32} {report.direct_assets_before:<20} {report.direct_assets_after:<20} {report.direct_assets_before - report.direct_assets_after:+d} assets\n")
        target.write("\n")

        # 2. Finding Resolution Breakdown
        target.write(f"{c_bold}2. FINDING RESOLUTION BREAKDOWN{c_reset}\n")
        target.write(f"   {'Rule ID':<10} {'Severity':<10} {'Status':<22} {'Original Finding Title':<40}\n")
        target.write(f"   {'-'*10} {'-'*10} {'-'*22} {'-'*40}\n")

        for f in report.finding_resolutions:
            st = f.resolution_status.value
            color = c_green if st == "RESOLVED" else (c_yellow if "MANUAL" in st or "PARTIAL" in st else c_red)
            title_trunc = f.original_gap_title[:38] + ".." if len(f.original_gap_title) > 40 else f.original_gap_title
            target.write(f"   {f.finding_identity.rule_id:<10} {f.original_severity.value:<10} {color}{st:<22}{c_reset} {title_trunc:<40}\n")
            target.write(f"      Evidence: {f.validation_evidence}\n")

        target.write("\n")

        # 3. Candidate Digital Twin Overlay Details
        if report.candidate_overlay_result:
            ov = report.candidate_overlay_result
            target.write(f"{c_bold}3. DIGITAL TWIN OVERLAY TOPOLOGICAL VERIFICATION{c_reset}\n")
            if ov.removed_relationships:
                target.write(f"   {c_green}Severed Unsafe Edges:{c_reset}\n")
                for e in ov.removed_relationships:
                    target.write(f"     • {e}\n")
            if ov.added_relationships:
                target.write(f"   {c_cyan}Established Scoped Edges:{c_reset}\n")
                for e in ov.added_relationships:
                    target.write(f"     • {e}\n")
            if ov.residual_sensitive_exposures:
                target.write(f"   {c_red}Residual Sensitive Exposures:{c_reset} {ov.residual_sensitive_exposures}\n")
            else:
                target.write(f"   {c_green}Sensitive Data Asset Isolation: CONFIRMED (0 CUI/PCI assets exposed){c_reset}\n")
            if ov.operational_warnings:
                target.write(f"   {c_yellow}Operational Warnings:{c_reset}\n")
                for w in ov.operational_warnings:
                    target.write(f"     ⚠ {w}\n")
            target.write("\n")

        # 4. Summary narrative
        target.write(f"{c_bold}4. DEPLOYMENT GATE CONCLUSION{c_reset}\n")
        target.write(f"   {report.summary_narrative}\n")
        target.write("=" * 100 + "\n")

        return buffer.getvalue()

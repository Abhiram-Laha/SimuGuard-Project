"""Terminal Console Reporter for SimuGuard AI.

Renders pre-flight simulation reports to stdout with ANSI colorization,
structured visual tables, and clear executive alert boxes.
"""

import sys
from typing import TextIO
from simuguard.models.enums import DeploymentVerdict, Severity
from simuguard.models.report import PreFlightSimulationReport


# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_GREEN = "\033[42m"


class TerminalReporter:
    """Renders formatted simulation reports to terminal console."""

    def __init__(self, out: TextIO = sys.stdout, use_color: bool = True):
        self.out = out
        self.use_color = use_color

    def _c(self, text: str, color_code: str) -> str:
        if not self.use_color:
            return text
        return f"{color_code}{text}{RESET}"

    def render(self, report: PreFlightSimulationReport) -> None:
        """Render the complete PreFlightSimulationReport to output stream."""
        # 1. Header Banner
        self.out.write("\n" + self._c("=" * 84, CYAN) + "\n")
        self.out.write(self._c("  🛡️  SIMUGUARD AI — HYBRID CLOUD & FIREWALL PRE-FLIGHT SIMULATION REPORT", BOLD + CYAN) + "\n")
        self.out.write(self._c("=" * 84, CYAN) + "\n\n")

        # 2. Verdict Alert Box
        verdict = report.deployment_verdict
        if verdict == DeploymentVerdict.BLOCK_DEPLOYMENT:
            v_box = f" {BG_RED}{WHITE}{BOLD} 🛑 VERDICT: BLOCK_DEPLOYMENT {RESET} "
            v_color = RED
        elif verdict == DeploymentVerdict.WARN_MANUAL_REVIEW:
            v_box = f" {BG_YELLOW}{WHITE}{BOLD} ⚠️  VERDICT: WARN_MANUAL_REVIEW {RESET} "
            v_color = YELLOW
        else:
            v_box = f" {BG_GREEN}{WHITE}{BOLD} ✅ VERDICT: ALLOW {RESET} "
            v_color = GREEN

        score_bar_filled = int(report.overall_risk_score / 10)
        score_bar = "[" + "█" * score_bar_filled + "░" * (10 - score_bar_filled) + "]"

        self.out.write(f"  📋 Ticket ID     : {self._c(report.change_ticket_id, BOLD + WHITE)}\n")
        self.out.write(f"  🚨 Risk Score    : {self._c(score_bar, v_color)} {self._c(str(report.overall_risk_score) + ' / 100', BOLD + v_color)}\n")
        self.out.write(f"  🛑 Gate Decision : {v_box}\n")
        if report.evaluated_file:
            self.out.write(f"  📁 Source File   : {self._c(report.evaluated_file, DIM)}\n")
        self.out.write(f"\n  💡 {self._c('Executive Summary:', BOLD + WHITE)}\n")
        self.out.write(f"     {report.executive_summary}\n\n")

        # 3. Section 1: Predicted Blast Radius
        self.out.write(self._c("-" * 84, CYAN) + "\n")
        self.out.write(self._c("  💥 1. PREDICTED INFRASTRUCTURE BLAST RADIUS", BOLD + MAGENTA) + "\n")
        self.out.write(self._c("-" * 84, CYAN) + "\n")

        if not report.predicted_affected_assets:
            self.out.write("     • No infrastructure nodes within predicted blast radius.\n")
        else:
            for asset in report.predicted_affected_assets:
                tier_color = RED if asset.blast_tier.value == "DIRECT" else YELLOW
                self.out.write(
                    f"     • {self._c(asset.asset_id, BOLD + WHITE)} "
                    f"[{self._c(asset.blast_tier.value, tier_color)}] "
                    f"({self._c(asset.criticality.value, DIM)}): "
                    f"{asset.impact_description}\n"
                )

        # 4. Section 2: Identified Security Gaps
        self.out.write("\n" + self._c("-" * 84, CYAN) + "\n")
        self.out.write(self._c("  ⚠️  2. DETECTED POLICY, GOVERNANCE & SECURITY GAPS", BOLD + YELLOW) + "\n")
        self.out.write(self._c("-" * 84, CYAN) + "\n")

        if not report.identified_security_gaps:
            self.out.write("     • No security or compliance gaps detected.\n")
        else:
            for idx, gap in enumerate(report.identified_security_gaps, 1):
                sev_color = RED if gap.severity == Severity.CRITICAL else (YELLOW if gap.severity == Severity.HIGH else BLUE)
                rule_tag = f"[{gap.rule_id}] " if gap.rule_id else ""
                self.out.write(f"  {idx}. {self._c('[' + gap.severity.value + ']', BOLD + sev_color)} {self._c(rule_tag + gap.gap_title, BOLD + WHITE)}\n")
                self.out.write(f"     ├─ Impact     : {gap.technical_impact}\n")
                self.out.write(f"     ├─ Compliance : {self._c(gap.compliance_violation, CYAN)}\n")
                if gap.remediation_guidance:
                    self.out.write(f"     └─ Remediation: {self._c(gap.remediation_guidance, GREEN)}\n")
                self.out.write("\n")

        # 5. Section 3: Pre-Implementation Validation Plan
        self.out.write(self._c("-" * 84, CYAN) + "\n")
        self.out.write(self._c("  🔍 3. PRE-IMPLEMENTATION VALIDATION PLAYBOOK (CLI VERIFICATION)", BOLD + BLUE) + "\n")
        self.out.write(self._c("-" * 84, CYAN) + "\n")

        if not report.pre_implementation_validation_plan:
            self.out.write("     • No manual CLI verification steps required.\n")
        else:
            for check in report.pre_implementation_validation_plan:
                self.out.write(f"  Step {check.step_number} [{self._c(check.target_component, BOLD)}]: {check.what_to_validate}\n")
                self.out.write(f"     💻 Command : {self._c(check.cli_command, CYAN)}\n")
                self.out.write(f"     ✔️  Pass    : {check.expected_pass_criteria}\n\n")

        # 6. Section 4: Safe Remediated Config
        self.out.write(self._c("-" * 84, CYAN) + "\n")
        self.out.write(self._c("  🔧 4. AUTO-SYNTHESIZED LEAST-PRIVILEGE REMEDIATION CONFIGURATION", BOLD + GREEN) + "\n")
        self.out.write(self._c("-" * 84, CYAN) + "\n")
        for line in report.safe_remediated_config.splitlines():
            self.out.write(f"  {line}\n")
        self.out.write(self._c("=" * 84, CYAN) + "\n\n")

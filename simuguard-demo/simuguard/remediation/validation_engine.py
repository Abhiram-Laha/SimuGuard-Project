"""Validation engine executing closed-loop re-analysis of candidate configurations.

Re-analyzes candidate configurations through the deterministic Phase 4 engine
over the isolated Candidate Digital Twin Overlay.
"""

from pathlib import Path
from typing import Optional, Tuple
from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.models.report import PreFlightSimulationReport
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.remediation.candidate_overlay import CandidateDigitalTwinOverlay
from simuguard.remediation.models import CandidateOverlayResult, RemediationPlan


class ValidationEngine:
    """Executes closed-loop re-analysis of candidate remediated configurations."""

    def __init__(
        self,
        base_analyzer: Optional[SimuGuardAnalyzer] = None,
        parser: Optional[TerraformHclParser] = None,
    ):
        self.analyzer = base_analyzer or SimuGuardAnalyzer()
        self.parser = parser or TerraformHclParser()
        self.overlay_engine = CandidateDigitalTwinOverlay(
            base_digital_twin=self.analyzer.dt,
            loader=self.analyzer.loader,
        )

    def validate_candidate_plan(
        self,
        plan: RemediationPlan,
        original_file_path: str,
    ) -> Tuple[PreFlightSimulationReport, CandidateOverlayResult]:
        """Validate a candidate remediation plan by re-running pre-flight simulation.

        Returns:
            Tuple of (post_remediation_report, CandidateOverlayResult)
        """
        # 1. Parse original file to get baseline resources
        orig_parsed = self.parser.parse_file(original_file_path)

        # 2. Parse candidate synthesized HCL string
        cand_parsed = self.parser.parse_string(
            content=plan.synthesized_candidate_hcl,
            filename=f"candidate_{Path(original_file_path).name}",
        )

        # 3. Create isolated Digital Twin overlay reflecting candidate configuration
        candidate_twin, overlay_result = self.overlay_engine.create_candidate_overlay(
            candidate_resources=cand_parsed.resources,
            original_resources=orig_parsed.resources,
        )

        # 4. Construct ephemeral analyzer backed by candidate overlay graph
        candidate_analyzer = SimuGuardAnalyzer(
            digital_twin=candidate_twin,
            dataset_loader=self.analyzer.loader,
        )

        # 5. Execute full deterministic Phase 4 simulation on candidate configuration
        post_report = candidate_analyzer.analyze_parsed_file(
            parsed_file=cand_parsed,
            change_ticket_id=plan.change_ticket_id,
        )

        return post_report, overlay_result

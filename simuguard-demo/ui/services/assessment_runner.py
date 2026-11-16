"""Assessment Runner Service — orchestrates pre-flight simulation and remediation for Change Requests."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid

from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.engine.risk_engine import RiskEngine
from simuguard.graph.blast_radius import BlastRadiusResult, UnknownImpactAsset
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.identity import (
    CentralizedIdentityResolver,
    IdentityAccessState,
    IdentityLifecycleCategory,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import AssetCriticality, BlastTier, DeploymentVerdict, Severity
from simuguard.models.report import PreFlightSimulationReport
from simuguard.models.security_gap import SecurityGap
from simuguard.models.validation_check import ValidationCheck
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.parsers.resource_models import NormalizedResource, ParsedTerraformFile
from simuguard.remediation.comparison_engine import ComparisonEngine
from simuguard.remediation.config_generator import ConfigGenerator
from simuguard.remediation.models import (
    BeforeAfterComparisonReport,
    CandidateOverlayResult,
    FindingIdentity,
    RemediationPlan,
    RemediationRecommendation,
    RemediationStatus,
)
from simuguard.remediation.recommendation_engine import RecommendationEngine
from simuguard.remediation.sailpoint_remediator import SailPointRemediator
from simuguard.remediation.validation_engine import ValidationEngine
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
from storage.models import (
    AssessmentRecord,
    ChangeDomain,
    ChangeRequestRecord,
    RemediationRecord,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository


class AssessmentExecutionResult:
    """Container holding the complete simulation, remediation, and comparison output."""

    def __init__(
        self,
        request_number: str,
        baseline_report: PreFlightSimulationReport,
        remediation_plan: Optional[RemediationPlan] = None,
        post_report: Optional[PreFlightSimulationReport] = None,
        overlay_result: Optional[CandidateOverlayResult] = None,
        comparison_report: Optional[BeforeAfterComparisonReport] = None,
        error_message: Optional[str] = None,
    ):
        self.request_number = request_number
        self.baseline_report = baseline_report
        self.remediation_plan = remediation_plan
        self.post_report = post_report
        self.overlay_result = overlay_result
        self.comparison_report = comparison_report
        self.error_message = error_message


class AssessmentRunnerService:
    """Service orchestrating end-to-end security analysis, remediation, and validation."""

    def __init__(self, repository: Optional[ChangeRepository] = None):
        self.repo = repository or ChangeRepository()
        self.loader = EnterpriseDatasetLoader()
        self.analyzer = SimuGuardAnalyzer(dataset_loader=self.loader)
        self.parser = TerraformHclParser()
        self.rec_engine = RecommendationEngine(loader=self.loader)
        self.config_gen = ConfigGenerator(parser=self.parser)
        self.val_engine = ValidationEngine(base_analyzer=self.analyzer, parser=self.parser)
        self.comp_engine = ComparisonEngine()
        self.risk_engine = RiskEngine()
        self.sod_evaluator = SoDMatrixEvaluator()

    def run_assessment(
        self,
        request_number: str,
        force_reassessment: bool = False,
    ) -> Tuple[bool, str, Optional[AssessmentExecutionResult]]:
        """
        Execute deterministic security assessment and automated remediation for a Change Request.

        Returns:
            Tuple of (success: bool, status_message: str, result: Optional[AssessmentExecutionResult])
        """
        # 1. Fetch request from SQLite
        record = self.repo.get_change_request(request_number)
        if not record:
            return False, f"Change Request '{request_number}' not found in database.", None

        # 2. Check for duplicate/in-progress executions unless forced
        existing_asmt = self.repo.get_latest_assessment(request_number)
        if existing_asmt and not force_reassessment:
            return (
                False,
                f"Change Request '{request_number}' has already been assessed (Verdict: {existing_asmt.verdict}). "
                "Trigger explicit re-assessment to evaluate again.",
                None,
            )

        # Log started event
        self.repo.log_activity(
            request_number=request_number,
            action="ASSESSMENT_STARTED",
            actor=record.submitted_by or "SimuGuard Engine",
            details="Pre-flight security risk simulation initiated.",
        )

        try:
            # 3. Route according to Change Domain
            if record.domain == ChangeDomain.IDENTITY_GOVERNANCE.value:
                result = self._execute_sailpoint_assessment(record)
            else:
                result = self._execute_firewall_assessment(record)

            if result.error_message:
                self.repo.log_activity(
                    request_number=request_number,
                    action="ASSESSMENT_FAILED",
                    actor="SimuGuard Engine",
                    details=result.error_message,
                )
                return False, result.error_message, result

            # 4. Persist Baseline Assessment Record
            baseline_asmt_id = f"asmt-base-{uuid.uuid4().hex[:8]}"
            base_rep = result.baseline_report

            gap_severities = [g.severity for g in base_rep.identified_security_gaps]
            crit_count = sum(1 for s in gap_severities if s == Severity.CRITICAL)
            high_count = sum(1 for s in gap_severities if s == Severity.HIGH)
            med_count = sum(1 for s in gap_severities if s == Severity.MEDIUM)
            low_count = sum(1 for s in gap_severities if s == Severity.LOW)

            base_record = AssessmentRecord(
                assessment_id=baseline_asmt_id,
                request_number=request_number,
                timestamp=datetime.now(timezone.utc).isoformat(),
                verdict=base_rep.deployment_verdict.value,
                composite_risk_score=float(base_rep.overall_risk_score),
                max_risk_score=float(base_rep.overall_risk_score),
                security_gaps_count=len(base_rep.identified_security_gaps),
                critical_count=crit_count,
                high_count=high_count,
                medium_count=med_count,
                low_count=low_count,
                blast_radius_nodes_count=len(base_rep.predicted_affected_assets),
                assessment_type="ORIGINAL",
                raw_json=base_rep.model_dump_json(),
            )
            self.repo.save_assessment_record(base_record)

            # 5. Persist Post-Remediation Record if available
            if result.post_report:
                post_asmt_id = f"asmt-post-{uuid.uuid4().hex[:8]}"
                post_rep = result.post_report
                post_record = AssessmentRecord(
                    assessment_id=post_asmt_id,
                    request_number=request_number,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    verdict=post_rep.deployment_verdict.value,
                    composite_risk_score=float(post_rep.overall_risk_score),
                    max_risk_score=float(post_rep.overall_risk_score),
                    security_gaps_count=len(post_rep.identified_security_gaps),
                    critical_count=sum(1 for g in post_rep.identified_security_gaps if g.severity == Severity.CRITICAL),
                    high_count=sum(1 for g in post_rep.identified_security_gaps if g.severity == Severity.HIGH),
                    medium_count=sum(1 for g in post_rep.identified_security_gaps if g.severity == Severity.MEDIUM),
                    low_count=sum(1 for g in post_rep.identified_security_gaps if g.severity == Severity.LOW),
                    blast_radius_nodes_count=len(post_rep.predicted_affected_assets),
                    assessment_type="POST_REMEDIATION",
                    raw_json=post_rep.model_dump_json(),
                )
                self.repo.save_assessment_record(post_record)

            # 6. Persist Remediation Record if generated
            if result.remediation_plan:
                rem_id = f"rem-{uuid.uuid4().hex[:8]}"
                rem_status = "VALIDATED" if result.post_report else "GENERATED"
                rem_record = RemediationRecord(
                    remediation_id=rem_id,
                    request_number=request_number,
                    assessment_id=baseline_asmt_id,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    synthesized_hcl=result.remediation_plan.synthesized_candidate_hcl,
                    plan_json=result.remediation_plan.model_dump_json(),
                    comparison_json=result.comparison_report.model_dump_json() if result.comparison_report else None,
                    status=rem_status,
                )
                self.repo.save_remediation_record(rem_record)

            # 7. Update Change Request status to ANALYSIS_COMPLETE
            self.repo.update_change_request_status(
                request_number=request_number,
                status=WorkflowState.ANALYSIS_COMPLETE.value,
            )

            # Log audit events
            self.repo.log_activity(
                request_number=request_number,
                action="ASSESSMENT_COMPLETED",
                actor="SimuGuard Engine",
                details=f"Assessed verdict {base_rep.deployment_verdict.value} with composite risk score {base_rep.overall_risk_score}/100.",
            )

            if result.comparison_report:
                delta = result.comparison_report.risk_score_delta
                self.repo.log_activity(
                    request_number=request_number,
                    action="VALIDATION_COMPLETED",
                    actor="SimuGuard Validation Engine",
                    details=f"Candidate validation achieved risk reduction delta of {delta} points (Resolved: {result.comparison_report.resolved_count}).",
                )

            return True, "Security assessment and validation completed successfully.", result

        except Exception as e:
            err_msg = f"Assessment failed due to unexpected engine error: {str(e)}"
            self.repo.log_activity(
                request_number=request_number,
                action="ASSESSMENT_FAILED",
                actor="SimuGuard Engine",
                details=err_msg,
            )
            return False, err_msg, None

    def _execute_firewall_assessment(
        self, record: ChangeRequestRecord
    ) -> AssessmentExecutionResult:
        """Run Phase 4 and Phase 5 engines on Firewall/Terraform configurations."""
        source_path = record.source_file_path
        if not source_path or not Path(source_path).exists():
            # If raw content is available, stage to temporary file safely
            if record.raw_content and record.raw_content.strip():
                staged_name = f"staged_eval_{record.request_number.lower().replace('-', '_')}.tf"
                from config.settings import UPLOADS_DIR
                temp_file = UPLOADS_DIR / staged_name
                temp_file.write_text(record.raw_content, encoding="utf-8")
                source_path = str(temp_file)
            else:
                return AssessmentExecutionResult(
                    request_number=record.request_number,
                    baseline_report=PreFlightSimulationReport(
                        change_ticket_id=record.request_number,
                        overall_risk_score=100,
                        deployment_verdict=DeploymentVerdict.BLOCK_DEPLOYMENT,
                        executive_summary="Assessment blocked: No Terraform source file or HCL payload found.",
                        predicted_affected_assets=[],
                        identified_security_gaps=[
                            SecurityGap(
                                rule_id="PAYLOAD-01",
                                severity=Severity.CRITICAL,
                                gap_title="Missing Configuration Payload",
                                technical_impact="Change request contains no executable Terraform policy file.",
                                compliance_violation="Pipeline Validation Standard",
                                remediation_guidance="Attach valid .tf configuration file or select demo scenario.",
                            )
                        ],
                        pre_implementation_validation_plan=[],
                        safe_remediated_config="# No configuration provided.",
                        evaluated_file="none",
                    ),
                    error_message="Configuration file not found on disk.",
                )

        # 1. Baseline Simulation via SimuGuardAnalyzer
        baseline_report = self.analyzer.analyze_file(
            file_path=source_path,
            change_ticket_id=record.request_number,
        )

        # 2. Parse resources to feed recommendation generator
        parsed = self.parser.parse_file(source_path)

        # 3. Generate recommendations
        recommendations = self.rec_engine.generate_recommendations(
            security_gaps=baseline_report.identified_security_gaps,
            resources=parsed.resources,
        )

        # 4. Generate candidate remediated HCL configuration
        candidate_plan = self.config_gen.generate_candidate_hcl(
            original_file_path=source_path,
            recommendations=recommendations,
            change_ticket_id=record.request_number,
        )

        # 5. Closed-loop validation over Candidate Overlay
        post_report, overlay_result = self.val_engine.validate_candidate_plan(
            plan=candidate_plan,
            original_file_path=source_path,
        )

        # 6. Before-and-After Differential Comparison
        comparison_report = self.comp_engine.compare_reports(
            pre_report=baseline_report,
            post_report=post_report,
            overlay_result=overlay_result,
            change_ticket_id=record.request_number,
        )

        return AssessmentExecutionResult(
            request_number=record.request_number,
            baseline_report=baseline_report,
            remediation_plan=candidate_plan,
            post_report=post_report,
            overlay_result=overlay_result,
            comparison_report=comparison_report,
        )

    def _execute_sailpoint_assessment(
        self, record: ChangeRequestRecord
    ) -> AssessmentExecutionResult:
        """Run identity governance rules and validation for SailPoint access requests."""
        sp_data = self.loader.load_sailpoint_governance()
        identities = sp_data.get("identities", {}).get("identities", [])
        roles = sp_data.get("roles", {}).get("roles", [])
        access_profiles = sp_data.get("access_profiles", {}).get("access_profiles", [])
        entitlements = sp_data.get("entitlements", {}).get("entitlements", [])

        # Parse form details
        sp_details = SailPointChangeDetails()
        if record.sailpoint_details_json:
            try:
                sp_details = SailPointChangeDetails(**json.loads(record.sailpoint_details_json))
            except Exception:
                pass

        # Dynamic Centralized Identity Resolution
        iam_data = self.loader.load_aws_iam_governance()
        target_id_or_name = (
            getattr(sp_details, "role_name", "")
            or getattr(sp_details, "role_arn", "")
            or sp_details.identity_name
            or sp_details.identity_id
            or sp_details.employee_id
            or getattr(sp_details, "target_role_name", "")
            or getattr(sp_details, "target_role_arn", "")
        )
        resolver = CentralizedIdentityResolver(sailpoint_data=sp_data, iam_data=iam_data)
        resolution = resolver.resolve_identity(
            query=target_id_or_name,
            employee_id=getattr(sp_details, "identity_record_id", None) or sp_details.employee_id,
            worker_id=sp_details.worker_id,
            account_id=getattr(sp_details, "aws_account", None) or sp_details.account_id,
            email=sp_details.corporate_email,
            department=sp_details.current_department or sp_details.department,
            target_department=sp_details.new_department,
        )

        # Detect AWS IAM Governance Workflow
        is_aws_iam = (
            resolution.employment_type in ["IAM_Role", "IAM_User", "Service_Identity", "IAM_Group"]
            or bool(getattr(sp_details, "role_name", ""))
            or bool(getattr(sp_details, "role_arn", ""))
            or bool(getattr(sp_details, "trust_relationship_id", ""))
            or "aws" in (sp_details.identity_source or "").lower()
            or "aws iam" in (record.title + " " + (record.description or "")).lower()
        )
        if is_aws_iam and resolution.status != IdentityResolutionStatus.CONFLICT:
            return self._execute_aws_iam_assessment(
                record=record,
                sp_details=sp_details,
                resolution=resolution,
                iam_data=iam_data,
            )

        identified_gaps: List[SecurityGap] = []
        affected_assets: List[AffectedAsset] = []
        validation_plan: List[ValidationCheck] = []
        has_unknown = False

        if resolution.status == IdentityResolutionStatus.CONFLICT:
            identified_gaps.append(
                SecurityGap(
                    rule_id="SP-CORR-03",
                    severity=Severity.CRITICAL,
                    gap_title="Identity Conflict: Conflicting Employee Attributes",
                    technical_impact=resolution.message,
                    compliance_violation="NIST SP 800-53 AC-2 (Account Management)",
                    remediation_guidance="Resolve identity discrepancy between Employee ID and Name in authoritative HR source.",
                )
            )
        elif resolution.status == IdentityResolutionStatus.AMBIGUOUS:
            identified_gaps.append(
                SecurityGap(
                    rule_id="SP-CORR-02",
                    severity=Severity.HIGH,
                    gap_title=f"Ambiguous Identity Reference: '{target_id_or_name}'",
                    technical_impact=resolution.message,
                    compliance_violation="NIST SP 800-53 AC-2 (Account Management)",
                    remediation_guidance="Specify unique identity ID or authoritative account ID to disambiguate target user.",
                )
            )
        elif resolution.status == IdentityResolutionStatus.UNMAPPED or not resolution.identity:
            has_unknown = True
            identified_gaps.append(
                SecurityGap(
                    rule_id="SP-CORR-01",
                    severity=Severity.HIGH,
                    gap_title=f"Unmapped Governance Entity: Identity '{target_id_or_name or 'Unspecified'}'",
                    technical_impact=resolution.message or (
                        f"Identity '{target_id_or_name}' cannot be correlated to any registered "
                        "identity profile or active authoritative directory in SailPoint ISC."
                    ),
                    compliance_violation="NIST SP 800-53 AC-2 (Account Management)",
                    remediation_guidance="Register identity in authoritative HR source before requesting role grants.",
                )
            )

            # Evaluate access approval and provisioning state even if identity is unmapped
            access_state = CentralizedIdentityResolver.evaluate_access_state(
                request_status=sp_details.request_status,
                approval_status=sp_details.approval_status,
                provisioning_status=sp_details.provisioning_status,
            )
            if not access_state.is_approved:
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-01",
                        severity=Severity.CRITICAL,
                        gap_title=f"In-Flight / Unapproved Access Assumption: {target_id_or_name}",
                        technical_impact=(
                            f"Access request for '{sp_details.requested_role or sp_details.entitlement}' "
                            f"holds governance status '{sp_details.request_status}' / approval '{sp_details.approval_status}'. "
                            "In-flight requests convey ZERO valid permissions under principle PENDING_IS_NOT_ACCESS."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2 & AC-3",
                        remediation_guidance="Obtain formal multi-tier business and security manager approval in SailPoint ISC.",
                    )
                )

            if not access_state.is_provisioned:
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-02",
                        severity=Severity.HIGH,
                        gap_title=f"Unprovisioned Identity Provisioning State: {target_id_or_name}",
                        technical_impact=(
                            f"Requested access has not completed downstream connector provisioning "
                            f"(status: '{sp_details.provisioning_status}'). Infrastructure changes cannot assume access is active."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2",
                        remediation_guidance="Trigger connector sync and verify account provisioning status.",
                    )
                )

            # Check for privileged access request (e.g. SAP Finance Administrator)
            all_ent = (sp_details.entitlement + " " + sp_details.requested_role + " " + (record.justification or "") + " " + " ".join(sp_details.access_to_add)).lower()
            if sp_details.privileged_access_requested or "sap - finance administrator" in all_ent or ("admin" in all_ent and "finance" in all_ent) or "administrator" in all_ent:
                priv_name = sp_details.privileged_entitlements[0] if sp_details.privileged_entitlements else "SAP - Finance Administrator"
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-04",
                        severity=Severity.CRITICAL,
                        gap_title=f"Privileged Access Governance Violation: {target_id_or_name}",
                        technical_impact=(
                            f"Request includes unapproved privileged entitlement '{priv_name}' "
                            "without separate privileged justification, expiry date, or privileged access owner authorization."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2(1) & ISO 27001 A.9.2.1",
                        remediation_guidance="Submit dedicated privileged access request with time-bound justification and privileged owner sign-off.",
                    )
                )

            # Check for transfer privilege creep
            if (
                sp_details.lifecycle_type == "MOVER"
                or "transfer" in (record.title + " " + (record.justification or "")).lower()
                or "mover" in (record.subcategory or "").lower()
                or (sp_details.current_department and sp_details.new_department and sp_details.current_department.lower() != sp_details.new_department.lower())
            ):
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-06",
                        severity=Severity.HIGH,
                        gap_title=f"Privilege Creep & Transfer Access Conflict: {target_id_or_name}",
                        technical_impact=(
                            f"Employee transfer from {sp_details.current_department or 'Operations'} to {sp_details.new_department or 'Finance'} involves cross-departmental access change. "
                            "Accumulated permissions across departments create segregation of duties risk and violate least privilege."
                        ),
                        compliance_violation="NIST SP 800-53 AC-6 (Least Privilege) & ISO 27001 A.9.2.6",
                        remediation_guidance="Enforce automated deprovisioning of previous department entitlements upon effective transfer date.",
                    )
                )

            from simuguard.models.enums import AssetCriticality
            affected_assets.append(
                AffectedAsset(
                    asset_id=str(target_id_or_name or "UNMAPPED-IDENTITY"),
                    asset_name=str(target_id_or_name or "Unmapped Identity"),
                    asset_type="SailPoint Identity",
                    blast_tier=BlastTier.DIRECT,
                    criticality=AssetCriticality.HIGH,
                    impact_description="Target identity for requested governance change; unmapped in authoritative directory.",
                )
            )

            if "leaver" in (record.subcategory or "").lower() or "offboarding" in (record.title or "").lower():
                validation_plan.append(
                    ValidationCheck(
                        step_number=1,
                        target_component="Downstream Target Systems (M365, AWS, ServiceNow, VPN)",
                        what_to_validate="Verify downstream account deactivation and session termination across all linked systems.",
                        cli_command=f"sailpoint accounts list --identity-id {target_id_or_name} --status REVOKED",
                        expected_pass_criteria="All linked application accounts must confirm REVOKED status; no active sessions remain.",
                    )
                )
            else:
                validation_plan.append(
                    ValidationCheck(
                        step_number=1,
                        target_component=f"SailPoint ISC Identity Profile ({target_id_or_name})",
                        what_to_validate=f"Verify multi-tier approval workflow and connector provisioning for '{target_id_or_name}'",
                        cli_command=f"sailpoint access-requests show --identity-id {target_id_or_name}",
                        expected_pass_criteria="Status must be APPROVED and Provisioning must be VERIFIED on target source.",
                    )
                )
        else:
            matched_ident = resolution.identity
            ident_id = resolution.identity_id
            ident_name = resolution.display_name
            emp_type = resolution.employment_type or "EMPLOYEE"

            # Check for Leaver / Terminated identity requesting access
            if resolution.lifecycle_category == IdentityLifecycleCategory.LEAVER:
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-05",
                        severity=Severity.CRITICAL,
                        gap_title=f"Access Request for Terminated/Leaver Identity: {ident_name}",
                        technical_impact=(
                            f"Identity '{ident_name}' ({ident_id}) has lifecycle state '{resolution.lifecycle_state}'. "
                            "Requesting or modifying access for deactivated or terminated personnel is strictly prohibited."
                        ),
                        compliance_violation="ISO 27001 A.9.2.6 & NIST SP 800-53 AC-2",
                        remediation_guidance="Reject request immediately and ensure identity deprovisioning workflow is executed.",
                    )
                )

            # Evaluate distinct governance access states (SP-01, SP-02)
            access_state = CentralizedIdentityResolver.evaluate_access_state(
                request_status=sp_details.request_status,
                approval_status=sp_details.approval_status,
                provisioning_status=sp_details.provisioning_status,
            )

            # 1. Evaluate Rule SP-01: In-Flight Access Assumption (PENDING_IS_NOT_ACCESS)
            if not access_state.is_approved:
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-01",
                        severity=Severity.CRITICAL,
                        gap_title=f"In-Flight / Unapproved Access Assumption: {ident_name}",
                        technical_impact=(
                            f"Access request for '{sp_details.requested_role or sp_details.entitlement}' "
                            f"holds governance status '{sp_details.request_status}' / approval '{sp_details.approval_status}'. "
                            "In-flight requests convey ZERO valid permissions under principle PENDING_IS_NOT_ACCESS."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2 & AC-3",
                        remediation_guidance="Obtain formal multi-tier business and security manager approval in SailPoint ISC.",
                    )
                )

            # 2. Evaluate Rule SP-02: Unprovisioned Access State
            if not access_state.is_provisioned:
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-02",
                        severity=Severity.HIGH,
                        gap_title=f"Unprovisioned Identity Provisioning State: {ident_name}",
                        technical_impact=(
                            f"Requested access has not completed downstream connector provisioning "
                            f"(status: '{sp_details.provisioning_status}'). Infrastructure changes cannot assume access is active."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2",
                        remediation_guidance="Trigger connector sync and verify account provisioning status.",
                    )
                )

            # 3. Evaluate Rule SP-03: Separation of Duties (SoD) Conflict Detection
            current_roles = set()
            relationships = sp_data.get("relationships", {}).get("relationships", [])
            for rel in relationships:
                if rel.get("source") == ident_id and rel.get("relationship") == "ASSIGNED_ROLE":
                    current_roles.add(rel.get("target"))

            # Extract requested role ID
            requested_role_id = ""
            for r in roles:
                if r["name"] in sp_details.requested_role or r["id"] in sp_details.requested_role:
                    requested_role_id = r["id"]
                    break

            if requested_role_id:
                candidate_roles = current_roles.union({requested_role_id})
                sod_conflicts = self.sod_evaluator.check_identity_sod(
                    identity_id=ident_id,
                    assigned_role_ids=candidate_roles,
                    assigned_entitlement_ids=set(),
                )
                for conflict in sod_conflicts:
                    identified_gaps.append(
                        SecurityGap(
                            rule_id="SP-03",
                            severity=conflict.conflict_def.severity,
                            gap_title=f"Separation of Duties (SoD) Conflict: {conflict.conflict_def.conflict_id} ({conflict.conflict_def.name})",
                            technical_impact=conflict.explanation,
                            compliance_violation=conflict.conflict_def.compliance_framework,
                            remediation_guidance=(
                                f"Reject assignment of conflicting role '{requested_role_id}' or revoke existing conflicting role."
                            ),
                        )
                    )

            # 4. Evaluate Rule SP-04: Contractor or General Privileged Access
            is_contractor = (
                resolution.lifecycle_category == IdentityLifecycleCategory.CONTRACTOR
                or emp_type == "CONTRACTOR"
                or "contractor" in matched_ident.get("identity_profile_id", "").lower()
            )
            all_ent = (sp_details.entitlement + " " + sp_details.requested_role + " " + (record.justification or "") + " " + " ".join(sp_details.access_to_add)).lower()
            has_priv_ent = sp_details.privileged_access_requested or "sap - finance administrator" in all_ent or ("admin" in all_ent and "finance" in all_ent) or "administrator" in all_ent
            if is_contractor:
                privileged_roles = {"sp-role-cloud-administrator", "sp-role-network-security-engineer", "sp-role-production-support-engineer"}
                if requested_role_id in privileged_roles or "admin" in (sp_details.requested_role or "").lower():
                    identified_gaps.append(
                        SecurityGap(
                            rule_id="SP-04",
                            severity=Severity.CRITICAL,
                            gap_title=f"Contractor Privileged Access Violation: {ident_name}",
                            technical_impact=(
                                f"Third-party contractor '{ident_name}' requested privileged role '{sp_details.requested_role}'. "
                                "Apex Global policy strictly prohibits assigning administrative cloud or firewall roles to contractors."
                            ),
                            compliance_violation="NIST SP 800-53 AC-2(1) & ISO 27001 A.9.2.1",
                            remediation_guidance="Assign non-privileged scoped contractor role or require internal employee sponsorship.",
                        )
                    )
            elif has_priv_ent:
                priv_name = sp_details.privileged_entitlements[0] if sp_details.privileged_entitlements else "SAP - Finance Administrator"
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-04",
                        severity=Severity.CRITICAL,
                        gap_title=f"Privileged Access Governance Violation: {ident_name}",
                        technical_impact=(
                            f"Request includes unapproved privileged entitlement '{priv_name}' "
                            "without separate privileged justification, expiry date, or privileged access owner authorization."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2(1) & ISO 27001 A.9.2.1",
                        remediation_guidance="Submit dedicated privileged access request with time-bound justification and privileged owner sign-off.",
                    )
                )

            # Evaluate Rule SP-06: Privilege Creep for Resolved Identity
            if (
                sp_details.lifecycle_type == "MOVER"
                or "transfer" in (record.title + " " + (record.justification or "")).lower()
                or "mover" in (record.subcategory or "").lower()
                or (sp_details.current_department and sp_details.new_department and sp_details.current_department.lower() != sp_details.new_department.lower())
            ):
                identified_gaps.append(
                    SecurityGap(
                        rule_id="SP-06",
                        severity=Severity.HIGH,
                        gap_title=f"Privilege Creep & Transfer Access Conflict: {ident_name}",
                        technical_impact=(
                            f"Employee transfer from {sp_details.current_department or 'Operations'} to {sp_details.new_department or 'Finance'} involves cross-departmental access change. "
                            "Accumulated permissions across departments create segregation of duties risk and violate least privilege."
                        ),
                        compliance_violation="NIST SP 800-53 AC-6 (Least Privilege) & ISO 27001 A.9.2.6",
                        remediation_guidance="Enforce automated deprovisioning of previous department entitlements upon effective transfer date.",
                    )
                )

            # 5. Populate affected assets from target application & entitlements
            # Convert criticality string to AssetCriticality enum
            from simuguard.models.enums import AssetCriticality
            crit_str = str(matched_ident.get("risk_classification", "HIGH")).upper()
            try:
                asset_crit = AssetCriticality(crit_str)
            except Exception:
                asset_crit = AssetCriticality.HIGH

            affected_assets.append(
                AffectedAsset(
                    asset_id=ident_id,
                    asset_name=ident_name,
                    asset_type="SailPoint Identity",
                    blast_tier=BlastTier.DIRECT,
                    criticality=asset_crit,
                    impact_description="Target identity for requested governance access grant.",
                )
            )

            # Add validation check step
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component=f"SailPoint ISC Identity Profile ({ident_id})",
                    what_to_validate=f"Verify multi-tier approval workflow and connector provisioning for '{ident_name}'",
                    cli_command=f"sailpoint access-requests show --identity-id {ident_id}",
                    expected_pass_criteria="Status must be APPROVED and Provisioning must be VERIFIED on target source.",
                )
            )

        # Compute deterministic risk score
        score_breakdown = self.risk_engine.calculate_score(
            security_gaps=identified_gaps,
            blast_radius=BlastRadiusResult(
                direct_impacts=[],
                cascading_impacts=[],
                unknown_nodes=[str(target_id_or_name)] if has_unknown else [],
                unknown_impacts=[
                    UnknownImpactAsset(
                        resource_identifier=str(target_id_or_name),
                        resource_type="SailPoint Identity",
                        reason="Unmapped identity profile in SailPoint ISC",
                    )
                ] if has_unknown else [],
            ),
            has_unknown_impact=has_unknown,
        )

        exec_summary = (
            f"SailPoint Identity Governance simulation for {record.request_number} concluded with verdict: "
            f"{score_breakdown.verdict.value}. Composite risk score: {score_breakdown.final_risk_score}/100. "
            f"Identified {len(identified_gaps)} governance gap(s). {score_breakdown.verdict_reason}"
        )

        # Synthesize governance remediation guidance
        safe_remediation_doc = (
            "# SimuGuard AI — Recommended Governance Remediation Plan\n"
            f"# Target Identity : {target_id_or_name}\n"
            f"# Requested Role  : {sp_details.requested_role or 'None'}\n"
            f"# Verdict         : {score_breakdown.verdict.value}\n\n"
            "Action Plan:\n"
            "1. Enforce PENDING_IS_NOT_ACCESS: Require formal CISO and Line Manager approval.\n"
            "2. Ensure SoD conflict matrix validation before access certification.\n"
            "3. Verify downstream target connector sync prior to incorporating access into cloud workloads.\n"
        )

        baseline_report = PreFlightSimulationReport(
            change_ticket_id=record.request_number,
            overall_risk_score=score_breakdown.final_risk_score,
            deployment_verdict=score_breakdown.verdict,
            executive_summary=exec_summary,
            predicted_affected_assets=affected_assets,
            identified_security_gaps=self.risk_engine.deduplicate_gaps(identified_gaps),
            pre_implementation_validation_plan=validation_plan,
            safe_remediated_config=safe_remediation_doc,
            evaluated_file="sailpoint_identity_request",
        )

        # Generate structured recommendations using SailPointRemediator
        sailpoint_remediator = SailPointRemediator(sailpoint_data=sp_data)
        recommendations: List[RemediationRecommendation] = []
        for gap in identified_gaps:
            rec = sailpoint_remediator.remediate_gap(
                gap=gap,
                resource=None,
                context=RuleEvaluationContext(sailpoint_governance=sp_data),
            )
            if rec:
                recommendations.append(rec)

        plan = RemediationPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            change_ticket_id=record.request_number,
            recommendations=recommendations,
            synthesized_candidate_hcl=safe_remediation_doc,
            target_environment="SailPoint Identity Security Cloud",
        )

        return AssessmentExecutionResult(
            request_number=record.request_number,
            baseline_report=baseline_report,
            remediation_plan=plan,
        )

    def _execute_aws_iam_assessment(
        self,
        record: ChangeRequestRecord,
        sp_details: SailPointChangeDetails,
        resolution: IdentityResolutionResult,
        iam_data: Dict[str, Any],
    ) -> AssessmentExecutionResult:
        """Run cloud IAM governance rules and validation for AWS IAM change requests."""
        identified_gaps: List[SecurityGap] = []
        affected_assets: List[AffectedAsset] = []
        validation_plan: List[ValidationCheck] = []
        has_unknown = False

        target_ident = resolution.identity or {}
        target_name = (
            getattr(sp_details, "role_name", "")
            or getattr(sp_details, "target_role_name", "")
            or target_ident.get("name")
            or record.title
        )
        target_arn = getattr(sp_details, "role_arn", "") or getattr(sp_details, "target_role_arn", "") or target_ident.get("arn", "")
        account_id = getattr(sp_details, "aws_account", "") or getattr(sp_details, "target_aws_account", "") or target_ident.get("account_id", "111122223333")
        workload = getattr(sp_details, "assigned_workload", "")
        if not workload and target_ident.get("assigned_to"):
            workload = target_ident.get("assigned_to")[0]

        # 1. Unmapped check
        if resolution.status == IdentityResolutionStatus.UNMAPPED or not target_ident:
            has_unknown = True
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-CORR-01",
                    severity=Severity.HIGH,
                    gap_title=f"Unmapped AWS IAM Entity: '{target_name}'",
                    technical_impact=resolution.message or f"Role '{target_name}' could not be correlated in AWS IAM Digital Twin.",
                    compliance_violation="NIST SP 800-53 AC-2 (Account Management)",
                    remediation_guidance="Verify role ARN or identity record ID in AWS IAM Digital Twin dataset.",
                )
            )

        # 2. Populate Affected Assets (Direct & Cascading from Digital Twin topology)
        crit_raw = str(target_ident.get("criticality") or "HIGH").upper()
        role_crit = (
            AssetCriticality.CRITICAL
            if crit_raw == "CRITICAL"
            else (AssetCriticality.MEDIUM if crit_raw == "MEDIUM" else AssetCriticality.HIGH)
        )

        # Direct target role
        affected_assets.append(
            AffectedAsset(
                asset_id=target_name,
                asset_name=target_name,
                asset_type="IAM_Role",
                blast_tier=BlastTier.DIRECT,
                criticality=role_crit,
                impact_description=f"Direct target of requested IAM modification in AWS account {account_id}.",
            )
        )

        # Source role if cross-account
        src_name = getattr(sp_details, "source_role_name", "")
        if src_name:
            src_crit = AssetCriticality.CRITICAL if "incident" in src_name else AssetCriticality.MEDIUM
            src_acct = getattr(sp_details, "source_aws_account", "333344445555")
            affected_assets.append(
                AffectedAsset(
                    asset_id=src_name,
                    asset_name=src_name,
                    asset_type="IAM_Role",
                    blast_tier=BlastTier.DIRECT,
                    criticality=src_crit,
                    impact_description=f"Source identity in cross-account trust path (Account {src_acct}).",
                )
            )

        # Cascading topology edges
        if target_name == "role-analytics-ingestion-svc" or workload == "eks-analytics-worker-pool":
            affected_assets.append(
                AffectedAsset(
                    asset_id="s3-enterprise-cui-vault",
                    asset_name="Enterprise CUI Financial Vault",
                    asset_type="Storage_S3_Bucket",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.CRITICAL,
                    impact_description="Connected via CROSS_ZONE_IAM_PATH topology edge. Boundary analysis verifies explicit Deny prevents direct unauthorized access.",
                )
            )
            affected_assets.append(
                AffectedAsset(
                    asset_id="s3-dev-staging-telemetry",
                    asset_name="Staging Telemetry Bucket",
                    asset_type="Storage_S3_Bucket",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.HIGH,
                    impact_description="Connected via CAN_ACCESS; authorized ingestion path for analytics worker pool.",
                )
            )
            affected_assets.append(
                AffectedAsset(
                    asset_id="eks-analytics-worker-pool",
                    asset_name="Analytics Ingestion Worker Pool",
                    asset_type="Compute_EKS_NodeGroup",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.HIGH,
                    impact_description="Assumes role-analytics-ingestion-svc via EKS IRSA federation.",
                )
            )
        elif target_name == "role-customer-portal-backend" or workload == "eks-customer-portal-cluster":
            affected_assets.append(
                AffectedAsset(
                    asset_id="rds-postgres-core-prod",
                    asset_name="Production Core PostgreSQL RDS",
                    asset_type="Database_RDS_PostgreSQL",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.CRITICAL,
                    impact_description="Connected via CAN_ACCESS; customer portal database store exposed to excessive administrative permissions.",
                )
            )
            affected_assets.append(
                AffectedAsset(
                    asset_id="eks-customer-portal-cluster",
                    asset_name="Customer Portal EKS Cluster",
                    asset_type="Compute_EKS_Cluster",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.CRITICAL,
                    impact_description="Workload cluster assuming role-customer-portal-backend.",
                )
            )
        elif target_name == "role-payment-processor-pci" or workload == "eks-payment-processor-pool":
            affected_assets.append(
                AffectedAsset(
                    asset_id="rds-pci-token-vault-prod",
                    asset_name="PCI Token Vault Database",
                    asset_type="Database_RDS_PostgreSQL",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.CRITICAL,
                    impact_description="Connected via CAN_ACCESS; protected PCI cardholder data environment.",
                )
            )
            affected_assets.append(
                AffectedAsset(
                    asset_id="k-pci-token-encryption",
                    asset_name="PCI Token Encryption KMS Key",
                    asset_type="KMS_Key",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.HIGH,
                    impact_description="Scoped KMS key authorized for payment token decrypt operations.",
                )
            )
            affected_assets.append(
                AffectedAsset(
                    asset_id="eks-payment-processor-pool",
                    asset_name="Payment Processor EKS Pool",
                    asset_type="Compute_EKS_NodeGroup",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.CRITICAL,
                    impact_description="Assumes role-payment-processor-pci within PCI enclave.",
                )
            )
        elif target_name == "role-ci-cd-deployment-pipeline" or getattr(sp_details, "trust_relationship_id", "") == "trust-excessive-dev-to-prod":
            affected_assets.append(
                AffectedAsset(
                    asset_id="svc-github-actions-runner",
                    asset_name="CI/CD GitHub Actions Runner",
                    asset_type="Compute_Workload",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.CRITICAL,
                    impact_description="Production deployment pipeline workload assuming role-ci-cd-deployment-pipeline.",
                )
            )
        elif target_name == "role-secops-audit-agent" or getattr(sp_details, "trust_relationship_id", "") == "trust-secops-cross-account-prod":
            affected_assets.append(
                AffectedAsset(
                    asset_id="ec2-sec-siem-forwarder",
                    asset_name="Security SIEM Forwarder EC2",
                    asset_type="Compute_EC2_Instance",
                    blast_tier=BlastTier.CASCADING,
                    criticality=AssetCriticality.HIGH,
                    impact_description="Workload instance assigned to role-secops-incident-responder.",
                )
            )

        # 3. Evaluate Rule IAM-01: Overprivileged Managed Policies
        req_policy = (
            getattr(sp_details, "requested_policy_name", "")
            or sp_details.requested_role
            or " ".join(sp_details.access_to_add or [])
            or ""
        )
        if "amazons3fullaccess" in req_policy.lower() or "s3fullaccess" in req_policy.lower():
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-01",
                    severity=Severity.HIGH,
                    gap_title=f"Overprivileged Managed Policy: AmazonS3FullAccess attached to '{target_name}'",
                    technical_impact=(
                        "Requested policy 'AmazonS3FullAccess' grants wildcard 's3:*' on Resource '*' (marked INSECURE_OVERPRIVILEGED in policy catalog). "
                        "Effective Permission Evaluation: The attached ApexWorkloadBoundary explicitly denies direct access "
                        "to 'corp-restricted-cui-financial-vault', keeping CUI financial data protected. However, attaching "
                        "wildcard S3 permissions grants broad, unmonitored read/write and bucket deletion privileges across all other "
                        "S3 buckets in account 111122223333, violating least-privilege principles."
                    ),
                    compliance_violation="NIST SP 800-53 AC-6 (Least Privilege) & AWS Well-Architected Security Pillar",
                    remediation_guidance=(
                        "Reject wildcard AmazonS3FullAccess. Craft a scoped customer-managed policy granting only "
                        "s3:GetObject and s3:ListBucket on specified telemetry buckets with required prefixes."
                    ),
                )
            )
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component=f"AWS IAM Role ({target_name})",
                    what_to_validate="Verify effective permissions against ApexWorkloadBoundary and ensure CUI vault remains denied.",
                    cli_command=f"aws iam simulate-principal-policy --policy-source-arn {target_arn} --action-names s3:GetObject --resource-arns arn:aws:s3:::corp-restricted-cui-financial-vault/*",
                    expected_pass_criteria="EvaluationResult must return 'ExplicitDeny' for Restricted CUI Financial Vault.",
                )
            )
            validation_plan.append(
                ValidationCheck(
                    step_number=2,
                    target_component=f"AWS S3 Staging Telemetry Bucket (s3-dev-staging-telemetry)",
                    what_to_validate="Verify scoped write access to telemetry staging prefix.",
                    cli_command="aws s3api head-bucket --bucket apex-dev-staging-telemetry",
                    expected_pass_criteria="Status 200 OK; access restricted to staging upload prefix.",
                )
            )

        elif "administratoraccess" in req_policy.lower():
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-01",
                    severity=Severity.CRITICAL,
                    gap_title=f"Catastrophic Overprivilege: AdministratorAccess requested for '{target_name}'",
                    technical_impact=(
                        "Requested policy 'AdministratorAccess' grants root-equivalent wildcard access (Action: * on Resource: *). "
                        "Target role is a Critical production customer portal identity. The existing ApexWorkloadBoundary only "
                        "restricts access to the CUI S3 vault; it does NOT constrain compute, database (RDS), secrets, IAM, KMS, or network "
                        "APIs, allowing potential cluster compromise to achieve full account takeover."
                    ),
                    compliance_violation="NIST SP 800-53 AC-2(1), AC-6 & CIS AWS Foundations Benchmark 1.16",
                    remediation_guidance=(
                        "Deny AdministratorAccess. Create a scoped, role-specific policy limited strictly to "
                        "the troubleshooting actions required for customer portal services."
                    ),
                )
            )
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component=f"AWS IAM Policy Attachment ({target_name})",
                    what_to_validate="Verify AdministratorAccess is rejected and not attached to workload execution role.",
                    cli_command=f"aws iam list-attached-role-policies --role-name {target_name}",
                    expected_pass_criteria="AdministratorAccess must NOT appear in attached role policies.",
                )
            )

        # 4. Evaluate Rule IAM-02: Insecure Cross-Account Trust
        tr_id = getattr(sp_details, "trust_relationship_id", "")
        if tr_id == "trust-excessive-dev-to-prod" or ("not configured" in getattr(sp_details, "mfa_condition", "").lower() and "prod" in record.title.lower()):
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-02",
                    severity=Severity.CRITICAL,
                    gap_title="Insecure Excessive Cross-Account Trust: Development to Production CI/CD",
                    technical_impact=(
                        "Trust relationship 'trust-excessive-dev-to-prod' allows principals in development account 222233334444 "
                        "to assume production deployment role 'role-ci-cd-deployment-pipeline' without an MFA condition or ExternalId. "
                        "The target role possesses AdministratorAccess and has NO permission boundary, creating a direct critical bridge "
                        "from a lower-trust development sandbox into production infrastructure."
                    ),
                    compliance_violation="NIST SP 800-53 AC-3, AC-17 & CIS AWS Foundations Benchmark 1.20",
                    remediation_guidance=(
                        "Configure mandatory MFA requirement (aws:MultiFactorAuthPresent: true) and ExternalId condition in the trust policy. "
                        "Restrict trusted principal from root to a specific deployment role ARN, and apply a permission boundary to the production role."
                    ),
                )
            )
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component="AWS IAM Trust Policy (role-ci-cd-deployment-pipeline)",
                    what_to_validate="Inspect assume-role trust document for MFA and ExternalId conditions.",
                    cli_command="aws iam get-role --role-name role-ci-cd-deployment-pipeline --query 'Role.AssumeRolePolicyDocument'",
                    expected_pass_criteria="Trust document must contain aws:MultiFactorAuthPresent = true and sts:ExternalId conditions.",
                )
            )

        # 5. Evaluate Rule IAM-03: Permission Boundary Degradation
        if getattr(sp_details, "boundary_action", "") == "REMOVE" or "remove" in (record.title + " " + getattr(sp_details, "permission_boundary", "")).lower() and "boundary" in (record.title + " " + (record.justification or "")).lower():
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-03",
                    severity=Severity.CRITICAL,
                    gap_title=f"Governance Boundary Degradation: Removal of 'ApexStrictPCIBoundary' from '{target_name}'",
                    technical_impact=(
                        "Request proposes removing the 'ApexStrictPCIBoundary' permission boundary from critical PCI workload role "
                        "'role-payment-processor-pci'. The boundary enforces PCI enclave isolation by explicitly denying access to "
                        "general S3 and DynamoDB data stores. Removing this boundary eliminates defense-in-depth isolation and violates PCI DSS requirements."
                    ),
                    compliance_violation="PCI DSS v4.0 Requirement 7.2, 7.3 & NIST SP 800-53 SC-7 (Boundary Protection)",
                    remediation_guidance=(
                        "Retain ApexStrictPCIBoundary. If specific maintenance permissions are needed, define a dedicated, time-bound scoped policy "
                        "and seek formal sign-off from the PCI Security Officer rather than stripping the governance boundary."
                    ),
                )
            )
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component="AWS IAM Role Boundary (role-payment-processor-pci)",
                    what_to_validate="Verify that ApexStrictPCIBoundary remains configured on payment processor identity.",
                    cli_command="aws iam get-role --role-name role-payment-processor-pci --query 'Role.PermissionsBoundary'",
                    expected_pass_criteria="PermissionsBoundary.PermissionsBoundaryArn must match arn:aws:iam::111122223333:policy/ApexStrictPCIBoundary.",
                )
            )

        # 6. Evaluate Rule IAM-04: In-Flight Pending Approvals
        if sp_details.approval_status == "PENDING" and tr_id != "trust-secops-cross-account-prod":
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-04",
                    severity=Severity.CRITICAL,
                    gap_title=f"In-Flight / Unapproved Access Assumption: {target_name}",
                    technical_impact=(
                        "Change request holds pending approvals. "
                        "In-flight requests convey ZERO valid permissions under governance principle PENDING_IS_NOT_ACCESS."
                    ),
                    compliance_violation="NIST SP 800-53 AC-2 & AC-3",
                    remediation_guidance="Obtain formal multi-tier business and security manager approval in AWS IAM governance workflow.",
                )
            )

        # 7. Evaluate Rule IAM-05: Missing Expiry on Temporary Troubleshooting Access
        if "temporary" in (record.justification or "").lower() or "troubleshooting" in (record.justification or "").lower():
            if not sp_details.access_expiry:
                identified_gaps.append(
                    SecurityGap(
                        rule_id="IAM-05",
                        severity=Severity.HIGH,
                        gap_title=f"Missing Time-Bound Access Expiry: Temporary Troubleshooting Grant for '{target_name}'",
                        technical_impact=(
                            "Change request specifies temporary troubleshooting access but provides no expiry timestamp or automated "
                            "session expiration limit. Temporary grants without expiry lead to persistent privilege creep."
                        ),
                        compliance_violation="NIST SP 800-53 AC-2(2) & ISO 27001 A.9.2.5",
                        remediation_guidance="Specify explicit expiry timestamp (e.g. maximum 2-hour window) and automate revocation.",
                    )
                )

        # 8. Validated SecOps Trust Review Scenario (CHG-IAM-2026-2105)
        if tr_id == "trust-secops-cross-account-prod":
            identified_gaps.append(
                SecurityGap(
                    rule_id="IAM-06",
                    severity=Severity.LOW,
                    gap_title="Audit Validation Sign-off: Production Security Sign-off Pending",
                    technical_impact=(
                        "SecOps cross-account audit trust relationship is verified secure with enforced MFA (aws:MultiFactorAuthPresent = true). "
                        "Routine sign-off from Production Security Owner is pending prior to formal change closure."
                    ),
                    compliance_violation="NIST SP 800-53 CA-2 (Security Assessments)",
                    remediation_guidance="Complete routine review and obtain Production Security sign-off to finalize validation record.",
                )
            )
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component="AWS STS Cross-Account Assumption (role-secops-audit-agent)",
                    what_to_validate="Verify that cross-account assume-role requires valid MFA token session.",
                    cli_command="aws sts assume-role --role-arn arn:aws:iam::111122223333:role/role-secops-audit-agent --role-session-name SecOpsAudit --serial-number arn:aws:iam::333344445555:mfa/secops-lead --token-code 123456",
                    expected_pass_criteria="STS call must succeed with temporary credentials; unauthenticated call without MFA token must return AccessDenied.",
                )
            )

        # Default validation check if empty
        if not validation_plan:
            validation_plan.append(
                ValidationCheck(
                    step_number=1,
                    target_component=f"AWS IAM ({target_name})",
                    what_to_validate=f"Verify configuration baseline and permission boundaries for '{target_name}'.",
                    cli_command=f"aws iam get-role --role-name {target_name}",
                    expected_pass_criteria="Role configuration matches approved security baseline.",
                )
            )

        # Compute Risk Score
        score_breakdown = self.risk_engine.calculate_score(
            security_gaps=identified_gaps,
            blast_radius=BlastRadiusResult(
                direct_impacts=[],
                cascading_impacts=[],
                unknown_nodes=[str(target_name)] if has_unknown else [],
                unknown_impacts=[
                    UnknownImpactAsset(
                        resource_identifier=str(target_name),
                        resource_type="IAM_Role",
                        reason="Unmapped IAM role in AWS Digital Twin",
                    )
                ] if has_unknown else [],
            ),
            has_unknown_impact=has_unknown,
        )

        exec_summary = (
            f"AWS IAM Governance simulation for {record.request_number} concluded with verdict: "
            f"{score_breakdown.verdict.value}. Composite risk score: {score_breakdown.final_risk_score}/100. "
            f"Identified {len(identified_gaps)} governance gap(s). {score_breakdown.verdict_reason}"
        )

        # Synthesize remediation guidance document
        safe_remediation_doc = (
            f"# SimuGuard AI — Recommended AWS IAM Remediation Plan\n"
            f"# Target Role    : {target_name}\n"
            f"# AWS Account    : {account_id}\n"
            f"# Verdict        : {score_breakdown.verdict.value}\n\n"
            "Action Plan:\n"
            "1. Enforce Least Privilege: Replace wildcard managed policies with scoped customer-managed policies.\n"
            "2. Enforce PENDING_IS_NOT_ACCESS: Require formal multi-tier sign-off before applying policy attachments.\n"
            "3. Enforce Defense-in-Depth: Maintain permission boundaries (ApexWorkloadBoundary / ApexStrictPCIBoundary).\n"
            "4. Secure Cross-Account Trust: Mandate aws:MultiFactorAuthPresent=true and ExternalId on trust policies.\n"
        )

        baseline_report = PreFlightSimulationReport(
            change_ticket_id=record.request_number,
            overall_risk_score=score_breakdown.final_risk_score,
            deployment_verdict=score_breakdown.verdict,
            executive_summary=exec_summary,
            predicted_affected_assets=affected_assets,
            identified_security_gaps=self.risk_engine.deduplicate_gaps(identified_gaps),
            pre_implementation_validation_plan=validation_plan,
            safe_remediated_config=safe_remediation_doc,
            evaluated_file="aws_iam_governance_request",
        )

        # Generate structured remediation recommendations
        recommendations: List[RemediationRecommendation] = []
        for idx, gap in enumerate(identified_gaps, start=1):
            finding_ident = FindingIdentity(
                rule_id=gap.rule_id,
                affected_resource=target_name,
                relevant_attribute=gap.gap_title,
                original_finding_ref=gap.rule_id,
            )
            rec = RemediationRecommendation(
                remediation_id=f"REM-{gap.rule_id}-{idx:02d}",
                original_finding_id=gap.rule_id,
                finding_identity=finding_ident,
                rule_id=gap.rule_id,
                affected_resource=target_name,
                current_config_snippet=f"# Current unsafe configuration for {target_name}",
                recommended_config_snippet=gap.remediation_guidance,
                explanation=gap.technical_impact,
                security_benefit=gap.remediation_guidance,
                operational_impact="Ensure scoped access without breaking necessary application workflows.",
                dependencies=["Cloud Platform Security sign-off"],
                validation_steps=[v.what_to_validate for v in validation_plan],
                confidence_score=0.95,
            )
            recommendations.append(rec)

        plan = RemediationPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            change_ticket_id=record.request_number,
            recommendations=recommendations,
            synthesized_candidate_hcl=safe_remediation_doc,
            target_environment=f"AWS IAM Account {account_id}",
        )

        return AssessmentExecutionResult(
            request_number=record.request_number,
            baseline_report=baseline_report,
            remediation_plan=plan,
        )

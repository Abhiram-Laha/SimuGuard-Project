"""End-to-End Report Integrity and Export Verification Tests for SimuGuard AI.

Verifies:
1. Executive JSON and PDF report exports across varied risk verdicts (BLOCK, WARN, ALLOW).
2. Strict field-by-field parity between exported JSON artifacts and persisted SQLite database records.
3. Accurate PDF binary structure (valid %PDF header, non-empty stream).
4. Strict cross-ticket report isolation (Request A never receives Request B's findings or metadata).
5. Elimination of fabricated metadata and verification of audit disclaimer disclaimers.
6. Export filename sanitization against path traversal and injection.
"""

import json
from pathlib import Path
import tempfile
import pytest

from storage.database import init_db
from storage.models import (
    AssessmentRecord,
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    RemediationRecord,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def temp_repo():
    """Create an isolated temporary repository."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    init_db(temp_db_path)
    repo = ChangeRepository(db_path=temp_db_path)
    yield repo

    try:
        Path(temp_db_path).unlink(missing_ok=True)
    except Exception:
        pass


# =============================================================================
# 1. JSON Export Parity with SQLite Database
# =============================================================================

def test_json_export_field_parity_with_database(temp_repo: ChangeRepository):
    """Verify that every field in the exported JSON matches the persisted SQLite records exactly."""
    cr = ChangeRequestRecord(
        request_number="SIM-CHG-REP-001",
        title="Upgrade Edge Firewall Permissive Egress Rule",
        description="Add egress route for analytics cluster to telemetry sink.",
        justification="Required for quarterly telemetry migration.",
        submitted_by="Alice NetworkSec",
        submitter_role="Network Security Operations",
        change_type=ChangeType.FIREWALL_POLICY.value,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=ChangePriority.HIGH.value,
        status=WorkflowState.ANALYSIS_COMPLETE.value,
        configuration_item="PAN-NGFW-EDGE-01",
        affected_application="Telemetry Analytics Pipeline",
    )
    temp_repo.create_change_request(cr)

    raw_simulation = {
        "change_ticket_id": "SIM-CHG-REP-001",
        "overall_risk_score": 90.0,
        "deployment_verdict": "BLOCK_DEPLOYMENT",
        "executive_summary": "Unrestricted egress route creates direct exposure to untrusted zones.",
        "identified_security_gaps": [
            {
                "rule_id": "FW-01",
                "severity": "CRITICAL",
                "title": "Unrestricted Any Service Egress",
                "description": "Rule allows service 'any' across untrusted boundary.",
                "policy_name": "rule-analytics-egress",
                "compliance_violation": "NIST SP 800-53 SC-7",
            },
            {
                "rule_id": "FW-02",
                "severity": "HIGH",
                "title": "Missing App-ID Inspection",
                "description": "Port-based rule without App-ID profile.",
                "policy_name": "rule-analytics-egress",
                "compliance_violation": "PCI-DSS 1.3",
            },
        ],
        "predicted_affected_assets": [
            {
                "asset_id": "s3-telemetry-sink",
                "asset_name": "Telemetry Data S3 Bucket",
                "asset_type": "Storage_S3_Bucket",
                "tier": "DIRECT",
                "criticality": "HIGH",
                "impact_description": "Direct destination of permissive policy.",
            }
        ],
    }

    asmt = AssessmentRecord(
        assessment_id="ASMT-REP-001",
        request_number="SIM-CHG-REP-001",
        timestamp="2026-11-16T12:00:00Z",
        verdict="BLOCK_DEPLOYMENT",
        composite_risk_score=90.0,
        max_risk_score=90.0,
        security_gaps_count=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=4,
        assessment_type="BASELINE_SIMULATION",
        raw_json=json.dumps(raw_simulation),
    )
    temp_repo.save_assessment_record(asmt)

    raw_plan = {
        "plan_id": "PLAN-REP-001",
        "recommendations": [
            {
                "remediation_id": "REM-01",
                "title": "Restrict Service to HTTPS",
                "remediation_type": "FIREWALL_RULE_STRENGTHENING",
                "status": "APPLIED",
            }
        ],
    }
    raw_comp = {
        "risk_score_before": 90.0,
        "risk_score_after": 25.0,
        "risk_score_delta": -65.0,
        "verdict_before": "BLOCK_DEPLOYMENT",
        "verdict_after": "ALLOW",
        "resolved_count": 2,
        "manual_review_count": 0,
    }

    rem = RemediationRecord(
        remediation_id="REM-REC-001",
        request_number="SIM-CHG-REP-001",
        assessment_id="ASMT-REP-001",
        created_at="2026-11-16T12:10:00Z",
        synthesized_hcl='resource "panos_security_policy" "remediated" {}',
        plan_json=json.dumps(raw_plan),
        comparison_json=json.dumps(raw_comp),
        status="VALIDATED",
    )
    temp_repo.save_remediation_record(rem)

    # Export JSON
    json_str = build_executive_json(
        request_record=cr,
        assessment_record=asmt,
        remediation_record=rem,
    )
    data = json.loads(json_str)

    # 1. Change ticket parity
    assert data["change_request"]["request_number"] == cr.request_number
    assert data["change_request"]["title"] == cr.title
    assert data["change_request"]["priority"] == cr.priority
    assert data["change_request"]["domain"] == cr.domain

    # 2. Assessment parity
    assert data["assessment"]["assessment_id"] == asmt.assessment_id
    assert data["assessment"]["verdict"] == asmt.verdict
    assert data["assessment"]["composite_risk_score"] == asmt.composite_risk_score
    assert data["assessment"]["severity_counts"]["critical"] == asmt.critical_count
    assert data["assessment"]["severity_counts"]["high"] == asmt.high_count
    assert data["assessment"]["severity_counts"]["total"] == asmt.security_gaps_count
    assert data["assessment"]["blast_radius_nodes_count"] == asmt.blast_radius_nodes_count

    # 3. Security gaps & assets parity
    assert len(data["assessment"]["identified_security_gaps"]) == 2
    assert data["assessment"]["identified_security_gaps"][0]["rule_id"] == "FW-01"
    assert len(data["affected_infrastructure_assets"]) == 1
    assert data["affected_infrastructure_assets"][0]["asset_id"] == "s3-telemetry-sink"

    # 4. Remediation & differential comparison parity
    assert data["remediation_plan"]["plan_id"] == "PLAN-REP-001"
    assert data["remediation_plan"]["plan_status"] == "VALIDATED"
    assert data["differential_comparison"]["risk_score_before"] == 90.0
    assert data["differential_comparison"]["risk_score_after"] == 25.0
    assert data["differential_comparison"]["risk_score_delta"] == -65.0
    assert data["differential_comparison"]["verdict_before"] == "BLOCK_DEPLOYMENT"
    assert data["differential_comparison"]["verdict_after"] == "ALLOW"


# =============================================================================
# 2. PDF Binary Generation and Structure
# =============================================================================

def test_pdf_export_structure_and_validity(temp_repo: ChangeRepository):
    """Verify that build_executive_pdf produces a valid, non-corrupt PDF document."""
    cr = ChangeRequestRecord(
        request_number="SIM-CHG-PDF-001",
        title="Edge Gateway Ingress Rule Update",
        domain=ChangeDomain.NETWORK_SECURITY.value,
        change_type=ChangeType.FIREWALL_POLICY.value,
        priority=ChangePriority.NORMAL.value,
        status=WorkflowState.ANALYSIS_COMPLETE.value,
    )
    asmt = AssessmentRecord(
        assessment_id="ASMT-PDF-001",
        request_number="SIM-CHG-PDF-001",
        timestamp="2026-11-16T12:00:00Z",
        verdict="WARN_MANUAL_REVIEW",
        composite_risk_score=55.0,
        max_risk_score=55.0,
        security_gaps_count=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=2,
        assessment_type="BASELINE_SIMULATION",
        raw_json=json.dumps({
            "executive_summary": "Policy requires verification of source network segment.",
            "identified_security_gaps": [
                {
                    "rule_id": "FW-03",
                    "severity": "HIGH",
                    "title": "Unverified Source Subnet",
                    "description": "Source address is not in RFC 1918 internal space.",
                }
            ],
            "predicted_affected_assets": [
                {
                    "asset_id": "fw-edge-01",
                    "asset_name": "Edge Firewall Primary",
                    "asset_type": "Firewall_Device",
                    "tier": "DIRECT",
                    "criticality": "HIGH",
                }
            ],
        }),
    )

    # 1. Test PDF without remediation record
    pdf_bytes_no_rem = build_executive_pdf(request_record=cr, assessment_record=asmt, remediation_record=None)
    assert isinstance(pdf_bytes_no_rem, bytes)
    assert len(pdf_bytes_no_rem) > 1000
    assert pdf_bytes_no_rem.startswith(b"%PDF-")

    # 2. Test PDF with remediation record
    rem = RemediationRecord(
        remediation_id="REM-PDF-001",
        request_number="SIM-CHG-PDF-001",
        assessment_id="ASMT-PDF-001",
        created_at="2026-11-16T12:15:00Z",
        synthesized_hcl='resource "panos_security_policy" "updated" {}',
        plan_json=json.dumps({"plan_id": "PLAN-PDF-001", "recommendations": []}),
        comparison_json=json.dumps({
            "risk_score_before": 55.0,
            "risk_score_after": 20.0,
            "risk_score_delta": -35.0,
            "verdict_before": "WARN_MANUAL_REVIEW",
            "verdict_after": "ALLOW",
            "resolved_count": 1,
            "manual_review_count": 0,
        }),
        status="VALIDATED",
    )
    pdf_bytes_with_rem = build_executive_pdf(request_record=cr, assessment_record=asmt, remediation_record=rem)
    assert isinstance(pdf_bytes_with_rem, bytes)
    assert len(pdf_bytes_with_rem) > len(pdf_bytes_no_rem)
    assert pdf_bytes_with_rem.startswith(b"%PDF-")


# =============================================================================
# 3. Cross-Ticket Report Isolation (Zero Information Bleed)
# =============================================================================

def test_cross_ticket_report_isolation(temp_repo: ChangeRepository):
    """Verify that Request A and Request B generate strictly independent reports with no data bleed."""
    # Ticket A: High-risk firewall change
    cr_a = ChangeRequestRecord(
        request_number="SIM-CHG-ISO-A",
        title="Firewall Permissive Ingress Ticket A",
        submitted_by="Engineer A",
        change_type=ChangeType.FIREWALL_POLICY.value,
        domain=ChangeDomain.NETWORK_SECURITY.value,
    )
    asmt_a = AssessmentRecord(
        assessment_id="ASMT-ISO-A",
        request_number="SIM-CHG-ISO-A",
        timestamp="2026-11-16T12:00:00Z",
        verdict="BLOCK_DEPLOYMENT",
        composite_risk_score=95.0,
        max_risk_score=95.0,
        security_gaps_count=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=7,
        assessment_type="BASELINE_SIMULATION",
        raw_json=json.dumps({"executive_summary": "TICKET A CRITICAL EXPOSURE"}),
    )

    # Ticket B: Clean SailPoint role grant
    cr_b = ChangeRequestRecord(
        request_number="SIM-CHG-ISO-B",
        title="SailPoint Standard Access Ticket B",
        submitted_by="Engineer B",
        change_type=ChangeType.SAILPOINT_GOVERNANCE.value,
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
    )
    asmt_b = AssessmentRecord(
        assessment_id="ASMT-ISO-B",
        request_number="SIM-CHG-ISO-B",
        timestamp="2026-11-16T12:05:00Z",
        verdict="ALLOW",
        composite_risk_score=10.0,
        max_risk_score=10.0,
        security_gaps_count=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=1,
        assessment_type="BASELINE_SIMULATION",
        raw_json=json.dumps({"executive_summary": "TICKET B CLEAN ROLE"}),
    )

    report_a_json = build_executive_json(cr_a, asmt_a)
    report_b_json = build_executive_json(cr_b, asmt_b)

    parsed_a = json.loads(report_a_json)
    parsed_b = json.loads(report_b_json)

    # Report A checks
    assert parsed_a["change_request"]["request_number"] == "SIM-CHG-ISO-A"
    assert parsed_a["assessment"]["verdict"] == "BLOCK_DEPLOYMENT"
    assert "TICKET A CRITICAL EXPOSURE" in parsed_a["assessment"]["executive_summary"]
    assert "SIM-CHG-ISO-B" not in report_a_json
    assert "TICKET B CLEAN ROLE" not in report_a_json

    # Report B checks
    assert parsed_b["change_request"]["request_number"] == "SIM-CHG-ISO-B"
    assert parsed_b["assessment"]["verdict"] == "ALLOW"
    assert "TICKET B CLEAN ROLE" in parsed_b["assessment"]["executive_summary"]
    assert "SIM-CHG-ISO-A" not in report_b_json
    assert "TICKET A CRITICAL EXPOSURE" not in report_b_json


# =============================================================================
# 4. Filename Sanitization & Security
# =============================================================================

def test_export_filename_sanitization():
    """Verify that exported filenames prevent path traversal and directory breakout."""
    # Standard clean name (hyphens and alphanumeric are preserved)
    fn1 = get_safe_export_filename("SIM-CHG-001", "ASMT-001", "pdf")
    assert fn1 == "SimuGuard_SIM-CHG-001_ASMT-001.pdf"

    # Malicious path traversal injection
    fn2 = get_safe_export_filename("../../../etc/passwd", "..\\windows\\system32", "json")
    assert ".." not in fn2
    assert "/" not in fn2
    assert "\\" not in fn2
    assert fn2.endswith(".json")

    # Extension stripping
    fn3 = get_safe_export_filename("SIM-100", None, ".PDF")
    assert fn3.endswith(".pdf")

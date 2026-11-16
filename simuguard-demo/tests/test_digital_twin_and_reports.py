"""Unit and integration tests for Digital Twin Explorer and Executive Reporting services (Milestone E)."""

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
from ui.services.digital_twin_service import (
    CATEGORY_COLORS,
    CATEGORY_MAPPINGS,
    DigitalTwinService,
)
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)


@pytest.fixture
def dt_service() -> DigitalTwinService:
    """Fixture providing the singleton DigitalTwinService."""
    return DigitalTwinService.get_instance()


@pytest.fixture
def temp_repo() -> ChangeRepository:
    """Fixture providing an isolated ChangeRepository backed by a temporary SQLite file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    init_db(temp_db_path)
    repo = ChangeRepository(db_path=temp_db_path)
    yield repo

    # Cleanup temp file
    try:
        Path(temp_db_path).unlink(missing_ok=True)
    except Exception:
        pass


@pytest.fixture
def sample_change_request() -> ChangeRequestRecord:
    """Fixture providing a valid ChangeRequestRecord."""
    return ChangeRequestRecord(
        request_number="SIM-2026-TEST-001",
        title="Test Perimeter Firewall Policy Update",
        description="Add allow rule for outbound monitoring traffic.",
        justification="Mandatory enterprise SIEM integration.",
        submitted_by="SecOps Lead",
        submitter_role="Network Security Operations",
        change_type=ChangeType.FIREWALL_POLICY.value,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=ChangePriority.NORMAL.value,
        status=WorkflowState.SUBMITTED.value,
        category="Network Security",
        subcategory="Security Policy Rule",
        assignment_group="SecOps-Network-Team",
        configuration_item="PAN-NGFW-EDGE-01",
        affected_application="Enterprise SIEM Collector",
    )


@pytest.fixture
def sample_assessment_record() -> AssessmentRecord:
    """Fixture providing an AssessmentRecord with structured raw_json payload."""
    raw_payload = {
        "change_ticket_id": "SIM-2026-TEST-001",
        "overall_risk_score": 85.5,
        "deployment_verdict": "BLOCK_DEPLOYMENT",
        "executive_summary": "Policy update introduces unrestricted egress to untrusted network zones without threat inspection.",
        "predicted_affected_assets": [
            {
                "asset_id": "net-zone-untrust",
                "asset_name": "Untrust-Internet",
                "asset_type": "Network_Zone",
                "tier": "DIRECT",
                "criticality": "HIGH",
                "impact_description": "Direct destination of permissive egress rule.",
            },
            {
                "asset_id": "s3-cust-data-vault",
                "asset_name": "Customer Data S3 Vault",
                "asset_type": "Storage_S3_Bucket",
                "tier": "CASCADING",
                "criticality": "CRITICAL",
                "impact_description": "Data store reachable via cascaded egress path containing CUI/PCI data.",
            },
        ],
        "identified_security_gaps": [
            {
                "rule_id": "FW-02",
                "severity": "CRITICAL",
                "gap_title": "Unrestricted Any/Any Egress Policy",
                "technical_impact": "Permits arbitrary outbound data exfiltration without App-ID or threat profile inspection.",
                "compliance_frameworks": ["NIST SP 800-53 SC-7", "PCI-DSS 1.3"],
                "remediation_guidance": "Restrict destination addresses and attach strict antivirus/vulnerability threat profiles.",
            },
            {
                "rule_id": "FW-03",
                "severity": "HIGH",
                "gap_title": "Omitted Threat Prevention Profile",
                "technical_impact": "Attacks and exploits will not be inspected or prevented at line rate.",
                "compliance_frameworks": ["CIS Controls 9.2"],
                "remediation_guidance": "Bind default-threat-prevention profile group to policy rule.",
            },
        ],
    }

    return AssessmentRecord(
        assessment_id="asmt-test-001",
        request_number="SIM-2026-TEST-001",
        timestamp="2026-11-16T12:00:00Z",
        verdict="BLOCK_DEPLOYMENT",
        composite_risk_score=85.5,
        max_risk_score=85.5,
        security_gaps_count=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=2,
        assessment_type="ORIGINAL",
        raw_json=json.dumps(raw_payload),
    )


@pytest.fixture
def sample_remediation_record() -> RemediationRecord:
    """Fixture providing a RemediationRecord with plan and comparison JSON."""
    plan_payload = {
        "plan_id": "plan-test-001",
        "change_ticket_id": "SIM-2026-TEST-001",
        "recommendations": [
            {
                "rule_id": "FW-02",
                "finding_title": "Unrestricted Any/Any Egress Policy",
                "action": "RESTRICT_DESTINATION_CIDR",
                "details": "Bound destination scope to 198.51.100.0/24.",
            }
        ],
        "synthesized_candidate_hcl": 'resource "panos_security_rule" "rule1" { destination = ["198.51.100.0/24"] }',
    }

    comparison_payload = {
        "change_ticket_id": "SIM-2026-TEST-001",
        "risk_score_before": 85.5,
        "risk_score_after": 15.0,
        "risk_score_delta": 70.5,
        "verdict_before": "BLOCK_DEPLOYMENT",
        "verdict_after": "ALLOW",
        "resolved_count": 2,
        "manual_review_count": 0,
        "finding_resolutions": [
            {
                "rule_id": "FW-02",
                "finding_title": "Unrestricted Any/Any Egress Policy",
                "status": "RESOLVED",
                "explanation": "Overly-permissive destination CIDR narrowed.",
            }
        ],
    }

    return RemediationRecord(
        remediation_id="rem-test-001",
        request_number="SIM-2026-TEST-001",
        assessment_id="asmt-test-001",
        created_at="2026-11-16T12:05:00Z",
        synthesized_hcl=plan_payload["synthesized_candidate_hcl"],
        plan_json=json.dumps(plan_payload),
        comparison_json=json.dumps(comparison_payload),
        status="VALIDATED",
    )


# =============================================================================
# Digital Twin Explorer Unit & Verification Tests
# =============================================================================

def test_digital_twin_exact_node_and_edge_counts(dt_service: DigitalTwinService):
    """Verify that the loaded Digital Twin graph contains exactly 220 nodes and 77 edges."""
    metrics = dt_service.get_metrics()
    assert metrics["node_count"] == 220, f"Expected exactly 220 nodes, got {metrics['node_count']}"
    assert metrics["edge_count"] == 77, f"Expected exactly 77 edges, got {metrics['edge_count']}"
    assert metrics["sensitive_assets_count"] >= 3, "Expected sensitive assets detected"
    assert "Apex Global" in metrics["organization"]


def test_digital_twin_category_breakdown(dt_service: DigitalTwinService):
    """Verify that all 220 nodes map cleanly into expected enterprise categories."""
    metrics = dt_service.get_metrics()
    cats = metrics["category_counts"]
    assert "Firewalls & Perimeter" in cats
    assert "Network Zones & Subnets" in cats
    assert "Cloud Infrastructure" in cats
    assert "Data Assets & Storage" in cats
    assert "SailPoint Identity Governance" in cats
    assert sum(cats.values()) == 220


def test_digital_twin_search_and_filter(dt_service: DigitalTwinService):
    """Verify query search and category/domain filtering."""
    # Search by text
    results_fw = dt_service.search_nodes(query="fw-edge")
    assert len(results_fw) > 0
    assert any("fw-edge" in r["id"].lower() or "fw-edge" in r["name"].lower() for r in results_fw)

    # Filter by category
    results_storage = dt_service.search_nodes(category="Data Assets & Storage")
    assert len(results_storage) > 0
    assert all(r["category"] == "Data Assets & Storage" for r in results_storage)

    # Filter by domain
    results_id = dt_service.search_nodes(domain="IDENTITY_GOVERNANCE")
    assert len(results_id) > 0
    assert all(r["category"] == "SailPoint Identity Governance" for r in results_id)


def test_digital_twin_get_node_details(dt_service: DigitalTwinService):
    """Verify detailed node inspection including incoming/outgoing directional edges."""
    details = dt_service.get_node_details("fw-edge-01-primary")
    assert details is not None
    assert details["id"] == "fw-edge-01-primary"
    assert details["category"] == "Firewalls & Perimeter"
    assert "outgoing_edges" in details
    assert "incoming_edges" in details
    assert details["total_relationships"] >= 1

    # Non-existent node returns None
    assert dt_service.get_node_details("non-existent-asset-999") is None


def test_digital_twin_generate_topology_svg(dt_service: DigitalTwinService):
    """Verify SVG rendering of topology subgraph."""
    svg_global = dt_service.generate_topology_svg(max_nodes=30)
    assert svg_global.startswith("<svg")
    assert svg_global.endswith("</svg>")
    assert "<circle" in svg_global
    assert "<line" in svg_global

    # Centered subgraph
    svg_centered = dt_service.generate_topology_svg(center_node_id="fw-edge-01-primary", max_nodes=20)
    assert "<svg" in svg_centered
    assert 'node_fw-edge-01-primary' in svg_centered


# =============================================================================
# Report Export Service Unit Tests
# =============================================================================

def test_safe_export_filename_sanitization():
    """Verify filename sanitization strips hazardous path traversal and special characters."""
    clean_pdf = get_safe_export_filename("SIM/2026:001*PR", "asmt..001", "pdf")
    assert "/" not in clean_pdf
    assert ":" not in clean_pdf
    assert "*" not in clean_pdf
    assert clean_pdf.endswith(".pdf")
    assert clean_pdf.startswith("SimuGuard_")

    clean_json = get_safe_export_filename("SIM-2026-0002", extension="json")
    assert clean_json == "SimuGuard_SIM-2026-0002_latest.json"


def test_build_executive_json_structure(
    sample_change_request: ChangeRequestRecord,
    sample_assessment_record: AssessmentRecord,
    sample_remediation_record: RemediationRecord,
):
    """Verify generated JSON adheres to schema_version 1.0.0 and contains all required sections."""
    json_out = build_executive_json(
        request_record=sample_change_request,
        assessment_record=sample_assessment_record,
        remediation_record=sample_remediation_record,
    )

    data = json.loads(json_out)
    assert data["schema_version"] == "1.0.0"
    assert "audit_metadata" in data
    assert data["audit_metadata"]["organization"] == "Apex Global Technologies"

    # Change ticket section
    assert data["change_ticket"]["request_number"] == "SIM-2026-TEST-001"
    assert data["change_ticket"]["domain"] == "NETWORK_SECURITY"

    # Simulation assessment section
    assert data["simulation_assessment"]["verdict"] == "BLOCK_DEPLOYMENT"
    assert data["simulation_assessment"]["composite_risk_score"] == 85.5
    assert len(data["simulation_assessment"]["security_gaps"]) == 2

    # Blast radius affected assets
    assert len(data["affected_infrastructure_assets"]) == 2

    # Remediation & validation diff
    assert data["remediation_plan"]["plan_id"] == "plan-test-001"
    assert data["differential_comparison"]["verdict_after"] == "ALLOW"
    assert data["differential_comparison"]["risk_score_delta"] == 70.5


def test_build_executive_json_without_remediation(
    sample_change_request: ChangeRequestRecord,
    sample_assessment_record: AssessmentRecord,
):
    """Verify JSON export succeeds even when no remediation plan exists yet."""
    json_out = build_executive_json(
        request_record=sample_change_request,
        assessment_record=sample_assessment_record,
        remediation_record=None,
    )

    data = json.loads(json_out)
    assert data["simulation_assessment"]["verdict"] == "BLOCK_DEPLOYMENT"
    assert data["remediation_plan"]["plan_id"] is None
    assert data["differential_comparison"]["risk_score_after"] is None


def test_build_executive_pdf_validity(
    sample_change_request: ChangeRequestRecord,
    sample_assessment_record: AssessmentRecord,
    sample_remediation_record: RemediationRecord,
):
    """Verify that build_executive_pdf outputs valid, non-empty PDF bytes starting with %PDF."""
    pdf_bytes = build_executive_pdf(
        request_record=sample_change_request,
        assessment_record=sample_assessment_record,
        remediation_record=sample_remediation_record,
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000, "PDF byte stream should be substantial (>1KB)"
    assert pdf_bytes.startswith(b"%PDF"), "Generated file must start with valid PDF magic bytes"


def test_build_executive_pdf_without_remediation(
    sample_change_request: ChangeRequestRecord,
    sample_assessment_record: AssessmentRecord,
):
    """Verify PDF export functions cleanly when remediation record is omitted."""
    pdf_bytes = build_executive_pdf(
        request_record=sample_change_request,
        assessment_record=sample_assessment_record,
        remediation_record=None,
    )

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000


# =============================================================================
# Repository and Historical Isolation Tests
# =============================================================================

def test_repository_preserves_assessments_and_remediations(
    temp_repo: ChangeRepository,
    sample_change_request: ChangeRequestRecord,
    sample_assessment_record: AssessmentRecord,
    sample_remediation_record: RemediationRecord,
):
    """Verify isolated repository correctly stores, retrieves, and updates records for reports."""
    temp_repo.create_change_request(sample_change_request)
    temp_repo.save_assessment(sample_assessment_record)
    temp_repo.save_remediation(sample_remediation_record)

    # Retrieval
    retrieved_asmt = temp_repo.get_latest_assessment(sample_change_request.request_number)
    assert retrieved_asmt is not None
    assert retrieved_asmt.assessment_id == "asmt-test-001"
    assert retrieved_asmt.verdict == "BLOCK_DEPLOYMENT"

    retrieved_rem = temp_repo.get_latest_remediation(sample_change_request.request_number)
    assert retrieved_rem is not None
    assert retrieved_rem.remediation_id == "rem-test-001"

    # KPI summary
    kpis = temp_repo.get_kpi_summary()
    assert kpis.total_requests == 1
    assert kpis.blocked_count == 1
    assert kpis.remediated_count == 1
    assert kpis.avg_risk_score == 85.5


def test_build_executive_pdf_with_special_characters(
    sample_change_request: ChangeRequestRecord,
    sample_remediation_record: RemediationRecord,
):
    """Verify PDF generator safely escapes XML special characters in title, findings, and descriptions."""
    sample_change_request.title = "Update Rules <Primary> & Secondary > Tertiary & 'Quaternary' \"Quoted\""
    raw_payload = {
        "change_ticket_id": sample_change_request.request_number,
        "overall_risk_score": 90.0,
        "deployment_verdict": "BLOCK_DEPLOYMENT",
        "executive_summary": "Policy <contains> unsafe & dangerous 'quoted' \"tokens\" > 0.",
        "predicted_affected_assets": [
            {
                "asset_id": "asset-special-<1>",
                "asset_name": "Vault & Database <Sensitive>",
                "asset_type": "Database_RDS_PostgreSQL",
                "tier": "DIRECT",
                "criticality": "CRITICAL",
            }
        ],
        "identified_security_gaps": [
            {
                "rule_id": "FW-SPECIAL",
                "severity": "CRITICAL",
                "gap_title": "Policy <Unrestricted> & Cleartext",
                "technical_impact": "Impact with <HTML> & 'tags' > 50%",
                "compliance_violation": "NIST & ISO/IEC",
                "remediation_guidance": "Fix <this> & that",
            }
        ],
    }

    asmt = AssessmentRecord(
        assessment_id="asmt-special-001",
        request_number=sample_change_request.request_number,
        timestamp="2026-11-16T12:00:00Z",
        verdict="BLOCK_DEPLOYMENT",
        composite_risk_score=90.0,
        raw_json=json.dumps(raw_payload),
    )

    pdf_bytes = build_executive_pdf(
        request_record=sample_change_request,
        assessment_record=asmt,
        remediation_record=sample_remediation_record,
    )

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000


def test_digital_twin_search_empty_and_whitespace(dt_service: DigitalTwinService):
    """Verify searching with empty or whitespace string returns default asset inventory."""
    results_empty = dt_service.search_nodes(query="", limit=20)
    assert len(results_empty) == 20

    results_ws = dt_service.search_nodes(query="   ", limit=20)
    assert len(results_ws) == 20


def test_digital_twin_filter_category_and_domain_conjunction(dt_service: DigitalTwinService):
    """Verify conjunction of category and domain filters."""
    # Identity category with Identity Governance domain matches
    res1 = dt_service.search_nodes(category="SailPoint Identity Governance", domain="IDENTITY_GOVERNANCE")
    assert len(res1) > 0

    # Identity category with Network Security domain yields zero matches
    res2 = dt_service.search_nodes(category="SailPoint Identity Governance", domain="NETWORK_SECURITY")
    assert len(res2) == 0

    # Firewall category with Network Security domain matches
    res3 = dt_service.search_nodes(category="Firewalls & Perimeter", domain="NETWORK_SECURITY")
    assert len(res3) > 0


def test_ui_page_imports_and_navigation():
    """Verify Milestone E UI views and navigation dispatches import and run without syntax errors."""
    from config.settings import PAGE_DIGITAL_TWIN, PAGE_REPORTS
    from ui.navigation import route_page
    from ui.pages.digital_twin import render_digital_twin_page
    from ui.pages.reports import render_reports_page

    assert callable(render_digital_twin_page)
    assert callable(render_reports_page)
    assert callable(route_page)

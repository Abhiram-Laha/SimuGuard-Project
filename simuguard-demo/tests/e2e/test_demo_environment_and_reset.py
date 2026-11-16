"""Automated Tests for Demo Environment, Idempotent Reset, and Isolation (Milestone G).

Verifies:
1. Complete initialization of the 5 certified demo scenarios.
2. Accurate deterministic baseline verdicts and scores for all 5 demo scenarios.
3. Idempotent demo database reset mechanism.
4. Strict database isolation: Production DB (simuguard_history.db) remains untouched with 0 records.
5. Scenario 4 (demo_safe_firewall.tf) evaluates cleanly to ALLOW with risk score 0.
6. Headless Streamlit AppTest verification of environment switching and guided demo tour.
"""

from pathlib import Path
import sqlite3
import pytest
from streamlit.testing.v1 import AppTest

from config.settings import CHANGES_DIR, DB_PATH, DEMO_DB_PATH
from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.models.enums import DeploymentVerdict
from storage.database import init_db
from ui.services.demo_service import DEMO_SCENARIO_CONFIGS, DemoEnvironmentService

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


def test_demo_environment_initialization():
    """Verify that DemoEnvironmentService seeds all 5 certified scenarios with expected assessments."""
    # Run clean initialization
    DemoEnvironmentService.initialize_demo_database(force=True)
    assert DEMO_DB_PATH.exists(), "Demo database file was not created"

    repo = DemoEnvironmentService.get_demo_repository()
    assert DemoEnvironmentService.is_demo_initialized() is True

    # 1. Verify all 5 demo requests exist
    for cfg in DEMO_SCENARIO_CONFIGS:
        req_no = cfg["request_number"]
        cr = repo.get_change_request(req_no)
        assert cr is not None, f"Demo request {req_no} missing from demo database"
        assert cr.request_number.startswith("SIM-DEMO-")

        # Verify baseline assessment
        asmt = repo.get_latest_assessment(req_no, assessment_type="ORIGINAL")
        assert asmt is not None, f"Baseline assessment missing for {req_no}"

    # 2. Verify exact verdicts for all 5 scenarios
    asmt_001 = repo.get_latest_assessment("SIM-DEMO-001", assessment_type="ORIGINAL")
    assert asmt_001.verdict == "BLOCK_DEPLOYMENT"
    assert asmt_001.composite_risk_score == 100.0

    asmt_002 = repo.get_latest_assessment("SIM-DEMO-002", assessment_type="ORIGINAL")
    assert asmt_002.verdict == "BLOCK_DEPLOYMENT"
    assert asmt_002.composite_risk_score == 100.0

    asmt_003 = repo.get_latest_assessment("SIM-DEMO-003", assessment_type="ORIGINAL")
    assert asmt_003.verdict == "BLOCK_DEPLOYMENT"

    asmt_004 = repo.get_latest_assessment("SIM-DEMO-004", assessment_type="ORIGINAL")
    assert asmt_004.verdict == "ALLOW"
    assert asmt_004.composite_risk_score == 0.0

    asmt_005 = repo.get_latest_assessment("SIM-DEMO-005", assessment_type="ORIGINAL")
    assert asmt_005.verdict == "WARN_MANUAL_REVIEW"
    assert asmt_005.composite_risk_score == 35.0


def test_demo_environment_idempotent_reset():
    """Verify that resetting the demo database cleanly restores the 5 scenarios without corrupting state."""
    repo = DemoEnvironmentService.get_demo_repository()

    # Add a dummy record using repository
    from storage.models import ChangeRequestRecord, ChangeType, ChangeDomain, WorkflowState
    dummy_rec = ChangeRequestRecord(
        request_number="SIM-TEST-MUTATE",
        title="Mutated Dummy Change",
        description="Testing reset behavior",
        submitted_by="Tester",
        domain=ChangeDomain.NETWORK_SECURITY.value,
        change_type=ChangeType.FIREWALL_POLICY.value,
        status=WorkflowState.DRAFT.value,
    )
    repo.create_change_request(dummy_rec)

    assert repo.get_change_request("SIM-TEST-MUTATE") is not None

    # Call reset
    DemoEnvironmentService.reset_demo_database()

    # Verify dummy record is gone and exactly 5 certified scenarios remain
    assert repo.get_change_request("SIM-TEST-MUTATE") is None
    all_demo_reqs = repo.list_change_requests(limit=100)
    assert len(all_demo_reqs) == 5
    assert all(r.request_number.startswith("SIM-DEMO-") for r in all_demo_reqs)


def test_demo_database_isolation_from_production():
    """Verify that demo operations never touch or mutate the production database."""
    # Ensure production DB exists
    init_db(DB_PATH)

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM change_requests")
    count = c.fetchone()[0]
    conn.close()

    assert count == 0, f"Production DB contains {count} records! Must remain strictly 0."


def test_safe_firewall_scenario_allows_cleanly():
    """Verify that changes/demo_safe_firewall.tf evaluates cleanly to score 0 and ALLOW."""
    safe_file = CHANGES_DIR / "demo" / "demo_safe_firewall.tf"
    if not safe_file.exists():
        safe_file = CHANGES_DIR / "demo_safe_firewall.tf"
    assert safe_file.exists(), "demo_safe_firewall.tf missing from changes directory"

    analyzer = SimuGuardAnalyzer()
    report = analyzer.analyze_file(str(safe_file.resolve()))

    assert report.deployment_verdict == DeploymentVerdict.ALLOW
    assert report.overall_risk_score == 0
    assert len(report.identified_security_gaps) == 0


def test_apptest_environment_switching_and_demo_tour():
    """Headless Streamlit verification of demo environment switching and guided tour elements."""
    app_path = WORKSPACE_ROOT / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)

    # 1. Launch in Demo Sandbox Mode
    at.session_state["environment_mode"] = "DEMO"
    at.session_state["show_guided_tour"] = True
    at.run()
    assert not at.exception
    # Check that Demo Sandbox notice is rendered
    assert any("Demo Sandbox Active" in m.value for m in at.markdown)

    # 2. Switch to Production Mode
    at.session_state["environment_mode"] = "PRODUCTION"
    at.run()
    assert not at.exception
    # Check that Production notice is rendered
    assert any("Production Mode Active" in m.value for m in at.markdown)

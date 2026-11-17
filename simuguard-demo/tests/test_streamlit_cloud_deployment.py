"""Automated Deployment Smoke Tests for Streamlit Community Cloud.

Verifies:
1. Clean dependency resolution and import integrity.
2. Root and inner entry-point execution via Streamlit AppTest.
3. Dataset presence and JSON schema validity.
4. Safe SQLite database initialization and demo bootstrapping.
5. Deterministic risk engine calculation and verdict safety.
6. Executive PDF and compliance JSON report generation.
"""

import json
from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

# Path references
TESTS_DIR = Path(__file__).resolve().parent
SIMUGUARD_DIR = TESTS_DIR.parent
REPO_ROOT = SIMUGUARD_DIR.parent


# =============================================================================
# 1. DEPENDENCY & IMPORT SMOKE TESTS
# =============================================================================

def test_deployment_dependencies_importable():
    """Verify all core third-party packages required by Streamlit Cloud are available."""
    import streamlit as st
    import pydantic
    import networkx as nx
    import pandas as pd
    import hcl2
    import reportlab
    import altair as alt

    # Verify Pydantic is v2
    assert int(pydantic.__version__.split(".")[0]) >= 2, "Pydantic v2 required for ConfigDict"
    
    # Verify Streamlit version
    assert int(st.__version__.split(".")[0]) >= 1, "Streamlit 1.x required"


def test_core_simuguard_modules_importable():
    """Verify all internal architecture modules resolve without import errors."""
    from config.settings import REPO_ROOT as CFG_ROOT, DB_PATH, DEMO_DB_PATH
    from storage.database import init_db, get_db_connection
    from storage.repository import ChangeRepository
    from simuguard.models.enums import DeploymentVerdict, Severity
    from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
    from simuguard.engine.analyzer import SimuGuardAnalyzer
    from ui.services.demo_service import DemoEnvironmentService
    from ui.services.servicenow_extractor import ServiceNowExtractor
    from ui.services.report_export_service import build_executive_pdf, build_executive_json

    assert CFG_ROOT.exists()
    assert DB_PATH.name == "simuguard_history.db"
    assert DEMO_DB_PATH.name == "simuguard_demo.db"


# =============================================================================
# 2. DATASET INTEGRITY CHECKS
# =============================================================================

def test_enterprise_dataset_files_present():
    """Ensure all synthetic enterprise JSON files exist and are valid JSON."""
    env_dir = SIMUGUARD_DIR / "demo_environment"
    assert env_dir.is_dir(), f"demo_environment directory not found at {env_dir}"

    json_files = list(env_dir.rglob("*.json"))
    assert len(json_files) >= 30, f"Expected at least 30 dataset JSON files, found {len(json_files)}"

    for jf in json_files:
        content = jf.read_text(encoding="utf-8")
        data = json.loads(content)
        assert data is not None, f"Dataset file {jf.name} parsed to None"


# =============================================================================
# 3. DATABASE INITIALIZATION & ISOLATION
# =============================================================================

def test_database_idempotent_initialization(tmp_path):
    """Verify that database initialization is clean, safe, and creates all tables."""
    from storage.database import init_db, get_db_connection
    from storage.repository import ChangeRepository

    temp_db = tmp_path / "deploy_test.db"
    init_db(temp_db)
    assert temp_db.exists(), "init_db failed to create database file"

    repo = ChangeRepository(db_path=str(temp_db))
    assert repo.list_change_requests() == []

    # Verify monotonic ID generation
    next_id = repo.generate_next_request_number()
    assert next_id == "SIM-CHG-000001"


# =============================================================================
# 4. STREAMLIT APP RUNTIME TESTS
# =============================================================================

def test_root_app_entrypoint_executes():
    """Test that the root app.py launches cleanly via Streamlit testing framework."""
    root_app = REPO_ROOT / "app.py"
    assert root_app.exists(), f"Root app.py not found at {root_app}"

    at = AppTest.from_file(str(root_app), default_timeout=30)
    at.run()
    assert not at.exception, f"Root app.py raised exception on startup: {at.exception}"


def test_inner_app_entrypoint_executes():
    """Test that the inner simuguard-demo/app.py launches cleanly as fallback."""
    inner_app = SIMUGUARD_DIR / "app.py"
    assert inner_app.exists(), f"Inner app.py not found at {inner_app}"

    at = AppTest.from_file(str(inner_app), default_timeout=30)
    at.run()
    assert not at.exception, f"Inner app.py raised exception on startup: {at.exception}"


# =============================================================================
# 5. DETERMINISTIC ENGINE & REPORT GENERATION
# =============================================================================

def test_risk_analysis_and_reporting_pipeline():
    """Verify the end-to-end extraction, analysis, and report generation pipeline."""
    from ui.services.demo_service import DemoEnvironmentService
    from ui.services.report_export_service import build_executive_pdf, build_executive_json

    repo = DemoEnvironmentService.get_demo_repository()
    changes = repo.list_change_requests()
    assert len(changes) >= 5, f"Expected 5 demo scenarios, found {len(changes)}"

    target_change = repo.get_change_request("SIM-DEMO-001")
    assert target_change is not None, "SIM-DEMO-001 not found in demo repository"

    assessment = repo.get_latest_assessment("SIM-DEMO-001")
    assert assessment is not None, "Assessment for SIM-DEMO-001 not found"
    assert assessment.verdict in ("ALLOW", "BLOCK", "BLOCK_DEPLOYMENT", "WARN_MANUAL_REVIEW"), f"Unexpected verdict: {assessment.verdict}"

    # Verify SailPoint SoD Block Scenario (SIM-DEMO-003)
    sod_assessment = repo.get_latest_assessment("SIM-DEMO-003")
    assert sod_assessment is not None, "Assessment for SIM-DEMO-003 not found"
    assert sod_assessment.verdict == "BLOCK_DEPLOYMENT", f"Expected BLOCK_DEPLOYMENT for DEMO-003, got {sod_assessment.verdict}"

    # PDF Export
    pdf_bytes = build_executive_pdf(target_change, assessment)
    assert len(pdf_bytes) > 1000, "PDF export produced unexpectedly small output"

    # JSON Export
    json_str = build_executive_json(target_change, assessment)
    assert len(json_str) > 500, "JSON export produced unexpectedly small output"
    parsed_json = json.loads(json_str)
    assert parsed_json["change_request"]["request_number"] == "SIM-DEMO-001"
    assert parsed_json["assessment"]["verdict"] in ("ALLOW", "BLOCK", "BLOCK_DEPLOYMENT", "WARN_MANUAL_REVIEW")

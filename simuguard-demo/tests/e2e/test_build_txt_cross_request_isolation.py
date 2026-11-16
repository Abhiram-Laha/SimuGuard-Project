"""E2E Tests for Cross-Request Isolation in Single Assessment Workspace (build.txt REQ-06)."""

import pytest
from streamlit.testing.v1 import AppTest
from ui.services.servicenow_extractor import ServiceNowExtractor


def test_cross_request_isolation_clears_previous_assessment_state():
    """Verify loading a new change request purges previous assessment results and prevents stale bleed."""
    app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
    app.run()

    # Step 1: Run assessment on CHG-1001 (ALLOW)
    chg_1001_text = ServiceNowExtractor.get_sample_chg_1001()
    app.session_state["servicenow_raw_text"] = chg_1001_text
    app.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(chg_1001_text)
    app.run()

    run_btns = [b for b in app.button if "Run Pre-Flight Assessment" in b.label]
    assert len(run_btns) >= 1
    run_btns[0].click().run()

    assert not app.exception
    assert "current_assessment_result" in app.session_state and app.session_state["current_assessment_result"] is not None
    res1 = app.session_state["current_assessment_result"]
    assert res1.baseline_report.deployment_verdict.value == "ALLOW"

    # Step 2: Now switch to CHG-1002 via sample button or new extraction
    chg_1002_btn = [b for b in app.button if "CHG-1002" in b.label]
    assert len(chg_1002_btn) >= 1
    chg_1002_btn[0].click().run()

    # Verify that previous assessment result was cleared!
    assert app.session_state["current_assessment_result"] is None, (
        "Previous assessment result must be cleared upon loading a new change request to prevent stale bleed!"
    )
    # Extracted config is now for CHG-1002
    cfg2 = app.session_state["extracted_config"]
    assert cfg2 is not None
    assert cfg2.destination_addresses == "any"
    assert "any" in cfg2.applications.lower()
    assert "Allow-Analytics-Internet-Access" in cfg2.rule_name

    # Step 3: Run assessment on CHG-1002 (BLOCK)
    run_btns2 = [b for b in app.button if "Run Pre-Flight Assessment" in b.label]
    run_btns2[0].click().run()

    assert not app.exception
    res2 = app.session_state["current_assessment_result"]
    assert res2 is not None
    assert res2.baseline_report.deployment_verdict.value == "BLOCK_DEPLOYMENT"
    assert int(round(res2.baseline_report.overall_risk_score)) == 100

    # Step 4: Switch to SailPoint request
    sp_text = ServiceNowExtractor.get_sample_sailpoint()
    extract_btn = [b for b in app.button if "Extract Configuration" in b.label]
    assert len(extract_btn) >= 1
    # Update text and click extract
    app.session_state["servicenow_raw_text"] = sp_text
    extract_btn[0].click().run()

    # Verify previous firewall assessment is cleared
    assert app.session_state["current_assessment_result"] is None, (
        "Assessment result must be cleared when extracting a new request."
    )
    cfg_sp = app.session_state["extracted_config"]
    assert cfg_sp.domain == "IDENTITY_GOVERNANCE"
    # Ensure firewall rule name didn't bleed into identity config
    assert cfg_sp.rule_name == ""

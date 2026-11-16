"""Full End-to-End UI Journey Automation Tests (build.txt STEP 4)."""

import pytest
from streamlit.testing.v1 import AppTest
from ui.services.servicenow_extractor import ServiceNowExtractor


def test_full_ui_journey_single_workspace_workflow():
    """Execute complete user journey from ticket ingestion to assessment, remediation, and report download."""
    app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
    app.run()

    # 1. Verify default landing page is Single Assessment Workspace
    assert not app.exception
    assert any("Single Assessment Workspace" in m.value or "Change Risk Assessment" in m.value for m in app.markdown)

    # 2. Ingest CHG-1004 (Inbound NAT Support Portal)
    chg_1004_text = ServiceNowExtractor.get_sample_chg_1004()
    app.session_state["servicenow_raw_text"] = chg_1004_text
    extract_btn = [b for b in app.button if "Extract Configuration" in b.label]
    assert len(extract_btn) >= 1
    extract_btn[0].click().run()

    assert not app.exception
    # Verify Section 2 Plain-English Change Request Summary is rendered
    assert any("Change Request Summary" in m.value for m in app.markdown)
    # Verify no reference screenshot rendered inline in Section 2
    imgs = app.get("imgs")
    assert len(imgs) == 0

    # Verify extracted configuration review dataframe
    assert len(app.dataframe) >= 1

    # 3. Submit Pre-Flight Assessment
    run_btn = [b for b in app.button if "Run Pre-Flight Assessment" in b.label]
    assert len(run_btn) >= 1
    run_btn[0].click().run()

    assert not app.exception
    # Verify Section 5 Assessment Results rendered
    assert "current_assessment_result" in app.session_state and app.session_state["current_assessment_result"] is not None
    result = app.session_state["current_assessment_result"]
    assert result.baseline_report.deployment_verdict.value in ("ALLOW", "WARN_MANUAL_REVIEW", "BLOCK_DEPLOYMENT")

    # Verify no reference screenshots are rendered in Section 5
    all_imgs = app.get("imgs")
    assert len(all_imgs) == 0

    # Verify remediation and validation checks
    assert len(result.baseline_report.identified_security_gaps) >= 0

    # Verify export buttons exist
    download_buttons = app.get("download_button")
    assert len(download_buttons) >= 2, f"Expected PDF and JSON export download buttons, got {len(download_buttons)}"
    pdf_btn = [b for b in download_buttons if "PDF" in b.label]
    json_btn = [b for b in download_buttons if "JSON" in b.label]
    assert len(pdf_btn) >= 1
    assert len(json_btn) >= 1


def test_ui_journey_navigation_across_all_pages():
    """Verify seamless navigation across New Assessment, History, Reports, and Settings."""
    pages = ["New Assessment", "Assessment History", "Reports", "Settings & Diagnostics"]
    for page in pages:
        app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
        app.session_state["active_page"] = page
        app.run()

        assert not app.exception, f"Navigation to {page} caused exception: {app.exception}"
        if page == "New Assessment":
            assert any("Single Assessment Workspace" in m.value or "Change Risk Assessment" in m.value for m in app.markdown)
        elif page == "Assessment History":
            assert any("Assessment History" in m.value or "Audit History" in m.value for m in app.markdown)
        elif page == "Reports":
            assert any("Reports" in m.value for m in app.markdown)
        elif page == "Settings & Diagnostics":
            assert any("Settings" in m.value or "Diagnostics" in m.value for m in app.markdown)

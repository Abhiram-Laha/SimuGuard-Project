"""Tests for UX Plain-English Change Request Summary and Affected Assets Rendering Fixes."""

from types import SimpleNamespace
import pytest
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import AssetCriticality, BlastTier
from ui.pages.workspace import (
    _get_screenshot_path,
    _render_blast_radius_tab,
    _render_change_request_summary,
    _render_embedded_screenshot,
    _render_findings_tab,
)
from ui.services.servicenow_extractor import (
    ChangeRequestSummary,
    ExtractedConfig,
    ServiceNowExtractor,
)


def test_change_request_summary_firewall_chg_1001():
    """Test 1: Change summary generated from CHG-1001 with correct structure."""
    text = ServiceNowExtractor.get_sample_chg_1001()
    cfg = ServiceNowExtractor.extract_from_text(text)
    summary = ServiceNowExtractor.generate_summary(cfg)

    assert isinstance(summary, ChangeRequestSummary)
    assert "Establish security policy rule" in summary.what_is_requested
    assert "Allow-Customer-Portal-API-HTTPS" in summary.what_is_requested
    assert summary.why_requested != "Not specified"
    assert "payment" in summary.why_requested.lower()
    assert summary.key_configuration_changes["Rule Action"] == "ALLOW"
    assert "Zone: Trust-Application" in summary.key_configuration_changes["Source Zone & CIDR"]
    assert "Zone: Untrust-Internet" in summary.key_configuration_changes["Destination Zone & CIDR"]
    assert any("Baseline" in obs or "Scoped" in obs for obs in summary.initial_observations)


def test_change_request_summary_firewall_chg_1002_wildcards():
    """Test 2 & 4: Wildcard values detected and preserved in summary for CHG-1002."""
    text = ServiceNowExtractor.get_sample_chg_1002()
    cfg = ServiceNowExtractor.extract_from_text(text)
    summary = ServiceNowExtractor.generate_summary(cfg)

    assert "any" in summary.key_configuration_changes["Destination Zone & CIDR"].lower()
    assert "any" in summary.key_configuration_changes["Application (App-ID)"].lower()
    assert any("Unrestricted Destination" in obs for obs in summary.initial_observations)
    assert any("App-ID Inspection Bypass" in obs for obs in summary.initial_observations)


def test_change_request_summary_firewall_chg_1005_vendor_modification():
    """Test 1 & 4: Vendor modification summary with all perimeter risk observations for CHG-1005."""
    text = ServiceNowExtractor.get_sample_chg_1005()
    cfg = ServiceNowExtractor.extract_from_text(text)
    summary = ServiceNowExtractor.generate_summary(cfg)

    assert "Modify" in summary.what_is_requested or "Allow-Vendor-Integration" in summary.what_is_requested
    assert summary.why_requested == (
        "The external vendor has reported connectivity issues while accessing its cloud-hosted services. "
        "The team proposes allowing unrestricted outbound access to resolve the issue immediately."
    )
    assert summary.key_configuration_changes["Security Profile Group"].lower() in ["none", "not specified"]
    assert "disabled" in summary.key_configuration_changes["Session Audit Logging"].lower()

    # Verify risky observations
    assert any("Unrestricted Destination" in obs for obs in summary.initial_observations)
    assert any("App-ID Inspection Bypass" in obs for obs in summary.initial_observations)
    assert any("Unrestricted Ports" in obs for obs in summary.initial_observations)
    assert any("Threat Prevention Inactive" in obs for obs in summary.initial_observations)
    assert any("Compliance Violation" in obs for obs in summary.initial_observations)


def test_all_five_firewall_requests_grounded_in_original_text_and_forbid_unsupported():
    """Verify all 5 firewall request summaries strictly preserve original text and contain no unsupported phrases."""
    sample_methods = [
        ("CHG-1001", ServiceNowExtractor.get_sample_chg_1001),
        ("CHG-1002", ServiceNowExtractor.get_sample_chg_1002),
        ("CHG-1003", ServiceNowExtractor.get_sample_chg_1003),
        ("CHG-1004", ServiceNowExtractor.get_sample_chg_1004),
        ("CHG-1005", ServiceNowExtractor.get_sample_chg_1005),
    ]

    for req_id, getter in sample_methods:
        raw_text = getter()
        cfg = ServiceNowExtractor.extract_from_text(raw_text)
        summary = ServiceNowExtractor.generate_summary(cfg)

        # 1. Grounding check: summary.why_requested must exist directly in the raw pasted text
        assert summary.why_requested != "Not specified in the submitted change request ticket.", f"{req_id} missing justification"
        assert summary.why_requested in raw_text, f"{req_id} justification was not grounded in original text: {summary.why_requested}"

    # 2. Strict check for CHG-2026-1005 exact justification
    chg_1005_text = ServiceNowExtractor.get_sample_chg_1005()
    cfg_1005 = ServiceNowExtractor.extract_from_text(chg_1005_text)
    summary_1005 = ServiceNowExtractor.generate_summary(cfg_1005)

    expected_1005 = (
        "The external vendor has reported connectivity issues while accessing its cloud-hosted services. "
        "The team proposes allowing unrestricted outbound access to resolve the issue immediately."
    )
    assert summary_1005.why_requested == expected_1005

    # 3. Forbid unsupported, invented, or hallucinated business justifications
    unsupported_phrases = [
        "diagnostic telemetry",
        "remote api synchronization",
        "remote api",
        "intermittent connectivity drops",
        "high-volume synchronizations",
        "without security inspection",
    ]
    for phrase in unsupported_phrases:
        assert phrase not in summary_1005.why_requested.lower(), f"Forbidden unsupported phrase '{phrase}' found in justification"
        assert phrase not in summary_1005.what_is_requested.lower(), f"Forbidden unsupported phrase '{phrase}' found in what_is_requested"


def test_business_justification_preserved_accurately():
    """Test 2: Business justification preserved exactly from original request text."""
    custom_text = """
Change Request: CHG-2026-9999
Short Description: Test Justification Preservation
Justification:
Critical quarterly compliance audit requires temporary egress tunnel to regulatory data broker.
Source Zone: Trust-Internal
Destination Zone: Untrust-Internet
Source CIDR: 10.0.0.1/32
Destination CIDR: 198.51.100.10/32
App-ID: ssl
Action: allow
"""
    cfg = ServiceNowExtractor.extract_from_text(custom_text)
    summary = ServiceNowExtractor.generate_summary(cfg)

    assert "Critical quarterly compliance audit requires temporary egress tunnel to regulatory data broker." in summary.why_requested


def test_missing_information_explicitly_not_specified():
    """Test 3: Missing information explicitly shows 'Not specified' without inventing data."""
    empty_cfg = ExtractedConfig(domain="NETWORK_SECURITY")
    summary = ServiceNowExtractor.generate_summary(empty_cfg)

    assert "Not specified" in summary.why_requested
    assert summary.key_configuration_changes["Security Policy Rule"] == "Not specified"
    assert "Not specified" in summary.key_configuration_changes["Source Zone & CIDR"]
    assert "Not specified" in summary.key_configuration_changes["Destination Zone & CIDR"]
    assert summary.key_configuration_changes["Application (App-ID)"] == "Not specified"


def test_affected_asset_schema_and_safe_attributes():
    """Test 5 & 6: AffectedAsset schema with and without data_classification and backward-compat properties."""
    # With data_classification
    asset_with_dc = AffectedAsset(
        asset_id="srv-prod-db-01",
        asset_name="Production Customer Database",
        asset_type="Database",
        criticality=AssetCriticality.CRITICAL,
        blast_tier=BlastTier.DIRECT,
        impact_description="Directly exposed by inbound rule modification",
        data_classification="PCI-DSS / CUI",
    )
    assert asset_with_dc.data_classification == "PCI-DSS / CUI"
    assert asset_with_dc.impact_rationale == "Directly exposed by inbound rule modification"
    assert asset_with_dc.compliance_violations == []

    # Without data_classification (defaults to None)
    asset_without_dc = AffectedAsset(
        asset_id="pan-ngfw-edge-01",
        asset_name="Internet Perimeter Firewall",
        asset_type="NGFW_Palo_Alto",
        criticality=AssetCriticality.HIGH,
        blast_tier=BlastTier.DIRECT,
        impact_description="Firewall policy modified",
    )
    assert asset_without_dc.data_classification is None
    assert asset_without_dc.impact_rationale == "Firewall policy modified"
    assert asset_without_dc.compliance_violations == []


def test_affected_assets_rendering_resilience_and_empty_message(monkeypatch):
    """Test 6 & 7: Rendering handles missing attributes and empty list gracefully without AttributeError."""
    import streamlit as st

    markdown_calls = []
    info_calls = []

    monkeypatch.setattr(st, "markdown", lambda content, **kwargs: markdown_calls.append(content))
    monkeypatch.setattr(st, "info", lambda content, **kwargs: info_calls.append(content))

    # 1. Empty assets list
    empty_rep = SimpleNamespace(predicted_affected_assets=[], identified_security_gaps=[])
    _render_findings_tab(empty_rep)

    assert any("No directly affected infrastructure assets were identified from the available Digital Twin data." in call for call in info_calls)

    # 2. Assets with missing attributes / None values
    incomplete_asset = SimpleNamespace(
        asset_id="node-test-01",
        # Missing asset_name, asset_type, criticality, blast_tier, data_classification, impact_rationale
    )
    rep_with_incomplete = SimpleNamespace(predicted_affected_assets=[incomplete_asset], identified_security_gaps=[])

    # Should execute without throwing AttributeError
    _render_findings_tab(rep_with_incomplete)
    assert any("node-test-01" in call for call in markdown_calls)
    assert any("Not available" in call for call in markdown_calls)


def test_apptest_single_workspace_renders_without_exceptions():
    """Test 8: Headless AppTest verifies entire workspace page renders without exceptions."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
    app.run()

    # Verify no exceptions or errors occurred on render
    assert not app.exception
    # Verify title or markdown present
    assert len(app.markdown) > 0 or len(app.title) > 0


def test_change_request_summary_native_table_rendering_no_raw_html():
    """Test: Verify Change Request Summary renders key configuration changes via native st.dataframe without raw HTML."""
    from streamlit.testing.v1 import AppTest

    test_samples = [
        ("CHG-1001", ServiceNowExtractor.get_sample_chg_1001),
        ("CHG-1002", ServiceNowExtractor.get_sample_chg_1002),
        ("CHG-1003", ServiceNowExtractor.get_sample_chg_1003),
        ("CHG-1004", ServiceNowExtractor.get_sample_chg_1004),
        ("CHG-1005", ServiceNowExtractor.get_sample_chg_1005),
    ]

    for req_id, getter in test_samples:
        raw_text = getter()
        app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
        app.session_state["servicenow_raw_text"] = raw_text
        app.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(raw_text)
        app.run()

        # 1. No unhandled Streamlit exceptions
        assert not app.exception, f"{req_id} caused exception: {app.exception}"

        # 2. Key configuration changes rendered via native Streamlit dataframe
        assert len(app.dataframe) >= 1, f"{req_id} did not render key configuration changes via st.dataframe"
        df = app.dataframe[0].value
        assert list(df.columns) == ["Parameter", "Extracted Value"], f"{req_id} columns incorrect: {df.columns}"

        # 3. Expected parameters present
        params = df["Parameter"].tolist()
        assert "Target Firewall" in params, f"{req_id} missing Target Firewall in parameters"
        assert "Security Policy" in params, f"{req_id} missing Security Policy in parameters"
        assert "Source Zone" in params, f"{req_id} missing Source Zone in parameters"
        assert "Source CIDR" in params, f"{req_id} missing Source CIDR in parameters"
        assert "Destination Zone" in params, f"{req_id} missing Destination Zone in parameters"
        assert "Destination CIDR" in params, f"{req_id} missing Destination CIDR in parameters"
        assert "Application" in params, f"{req_id} missing Application in parameters"

        # 4. No literal HTML entities in values
        for val in df["Extracted Value"].tolist():
            val_str = str(val)
            assert "&amp;" not in val_str, f"{req_id} contains literal &amp;: {val_str}"
            assert "&lt;" not in val_str, f"{req_id} contains literal &lt;: {val_str}"
            assert "&gt;" not in val_str, f"{req_id} contains literal &gt;: {val_str}"

        # 5. No raw HTML table tags in markdown outputs
        for m in app.markdown:
            val_m = m.value
            assert "<tr style=" not in val_m, f"{req_id} markdown contains raw <tr> tag: {val_m[:100]}"
            assert "<td style=" not in val_m, f"{req_id} markdown contains raw <td> tag: {val_m[:100]}"
            assert "<table style=" not in val_m, f"{req_id} markdown contains raw <table> tag: {val_m[:100]}"


def test_inline_screenshots_rendered_in_change_summary_and_affected_assets():
    """Verify change_request_summary.png and directly_affected_infrastructure_assets.png render inline via st.image."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
    raw_text = ServiceNowExtractor.get_sample_chg_1001()
    app.session_state["servicenow_raw_text"] = raw_text
    app.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(raw_text)
    app.run()

    # Section 2 Change Request Summary screenshot check
    assert not app.exception
    imgs = app.get("imgs")
    assert len(imgs) >= 1
    summary_img = imgs[0]
    assert "Change Request Summary" in summary_img.proto.imgs[0].caption
    # width = -5 confirms use_container_width=True
    assert summary_img.proto.width == -5

    # Run assessment to reveal Findings & Affected Assets tab
    buttons = [b for b in app.button if "Run Pre-Flight Assessment" in b.label]
    assert len(buttons) >= 1
    buttons[0].click().run()

    assert not app.exception
    imgs_after = app.get("imgs")
    assert len(imgs_after) >= 2
    captions = [im.proto.imgs[0].caption for im in imgs_after]
    assert any("Change Request Summary" in c for c in captions)
    assert any("Directly Affected Infrastructure Assets" in c for c in captions)
    for im in imgs_after:
        assert im.proto.width == -5  # container width responsive


def test_screenshot_defensive_path_resolution_and_missing_fallback(monkeypatch):
    """Verify fallback handling when screenshot files are missing without raising uncaught exceptions."""
    import streamlit as st

    # 1. Nonexistent file returns None
    missing_path = _get_screenshot_path("nonexistent_test_image_12345.png")
    assert missing_path is None

    # 2. Existing files return valid resolved Path
    summary_path = _get_screenshot_path("change_request_summary.png")
    assert summary_path is not None
    assert summary_path.is_file()

    assets_path = _get_screenshot_path("directly_affected_infrastructure_assets.png")
    assert assets_path is not None
    assert assets_path.is_file()

    # 3. Missing file triggers warning without unhandled exception
    warnings = []
    monkeypatch.setattr(st, "warning", lambda msg: warnings.append(msg))
    _render_embedded_screenshot("nonexistent_test_image_12345.png", caption="Test Missing")
    assert any("unavailable" in w.lower() or "not found" in w.lower() for w in warnings)

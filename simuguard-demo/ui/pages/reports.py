"""Reports & Compliance Exports Page — generate publication-grade executive PDFs and structured audit JSONs."""

import html
import json
from typing import Any, Dict, List, Optional
import streamlit as st

from config.settings import PAGE_NEW_ASSESSMENT, PAGE_NEW_CHANGE, PAGE_RESULTS
from storage.models import AssessmentRecord, ChangeDomain, ChangeRequestRecord, RemediationRecord
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_metric_card
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)


def render_reports_page(repository: ChangeRepository) -> None:
    """Render the executive reports management and export interface."""
    render_page_header(
        title="Reports & Compliance Exports",
        description="Generate executive PDF reports and audit-ready JSON exports for Change Advisory Board (CAB) review.",
    )

    all_requests = repository.list_change_requests(limit=100)
    kpis = repository.get_kpi_summary()

    # 1. Executive Summary Metric Cards
    col_k1, col_k2, col_k3, col_k4, col_k5 = st.columns(5)
    with col_k1:
        render_metric_card(
            label="Total Changes",
            value=kpis.total_requests,
            hint="Logged in repository",
        )
    with col_k2:
        render_metric_card(
            label="Allowed Changes",
            value=kpis.allowed_count,
            hint="Approved for deploy",
        )
    with col_k3:
        render_metric_card(
            label="Warning / Review",
            value=kpis.warn_count,
            hint="CAB manual review",
        )
    with col_k4:
        render_metric_card(
            label="Blocked Changes",
            value=kpis.blocked_count,
            hint="High-risk violations",
        )
    with col_k5:
        score_val = f"{kpis.avg_risk_score:.1f}" if kpis.total_requests > 0 else "0.0"
        render_metric_card(
            label="Avg Risk Score",
            value=f"{score_val}/100",
            hint="All simulated changes",
        )

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    if not all_requests:
        st.markdown(
            """
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">📑</div>
                <div class="sg-empty-title">No Change Requests Found</div>
                <div class="sg-empty-subtitle">
                    Submit a Change Request and run pre-flight simulation to generate executive reports and audit exports.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        col_e1, col_e2, col_e3 = st.columns([1, 1, 1])
        with col_e2:
            if st.button("New Risk Assessment →", use_container_width=True, key="btn_rep_to_new_change"):
                st.session_state["active_page"] = PAGE_NEW_ASSESSMENT
                st.rerun()
        return

    # 2. Filter & Search Controls Toolbar
    st.markdown(
        """
        <div class="sg-card" style="padding: 1rem 1.25rem 0.5rem 1.25rem; margin-bottom: 1.25rem;">
            <div style="font-size: 0.82rem; font-weight: 700; color: #475569; text-transform: uppercase; margin-bottom: 0.5rem;">
                Filter & Search Compliance Reports
            </div>
        """,
        unsafe_allow_html=True,
    )

    col_s1, col_s2, col_s3 = st.columns([2.5, 1.2, 1.2])
    with col_s1:
        search_query = st.text_input(
            "Search Request #, Title, or Configuration Item",
            placeholder="e.g. SIM-2026-0001, PAN-NGFW, AWS, SailPoint...",
            key="reports_search_query",
        )
    with col_s2:
        verdict_filter = st.selectbox(
            "Filter by Verdict",
            options=["ALL", "ALLOW", "WARN_MANUAL_REVIEW", "BLOCK_DEPLOYMENT", "PENDING_ASSESSMENT"],
            index=0,
            key="reports_verdict_filter",
        )
    with col_s3:
        domain_filter = st.selectbox(
            "Filter by Domain",
            options=["ALL", "NETWORK_SECURITY", "IDENTITY_GOVERNANCE"],
            index=0,
            key="reports_domain_filter",
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # 3. Filter Records
    matching_records: List[tuple[ChangeRequestRecord, Optional[AssessmentRecord], Optional[RemediationRecord]]] = []

    for req in all_requests:
        asmt = repository.get_latest_assessment(req.request_number)
        rem = repository.get_latest_remediation(req.request_number)

        # Domain filter
        if domain_filter != "ALL" and req.domain != domain_filter:
            continue

        # Verdict filter
        if verdict_filter != "ALL":
            if verdict_filter == "PENDING_ASSESSMENT" and asmt is not None:
                continue
            if verdict_filter != "PENDING_ASSESSMENT" and (not asmt or asmt.verdict != verdict_filter):
                continue

        # Text search
        if search_query and search_query.strip():
            q = search_query.strip().lower()
            match_no = q in req.request_number.lower()
            match_title = q in req.title.lower()
            match_ci = q in (req.configuration_item or "").lower()
            match_app = q in (req.affected_application or "").lower()
            if not (match_no or match_title or match_ci or match_app):
                continue

        matching_records.append((req, asmt, rem))

    # 4. Results Header & Count
    st.markdown(
        f"""
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <span style="font-weight:600; font-size:0.92rem; color:#1e293b;">
                Compliance Assessment Records ({len(matching_records)} found)
            </span>
            <span style="font-size:0.8rem; color:#64748b;">
                PDF & JSON exports adhere to Change Advisory Board (CAB) audit standards
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not matching_records:
        st.markdown(
            """
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:2rem; text-align:center; color:#64748b;">
                No Change Requests match the selected filters.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # 5. Render Each Assessment Card with Download Buttons
    for req, asmt, rem in matching_records:
        req_no = req.request_number
        domain_label = "Network Security" if req.domain == ChangeDomain.NETWORK_SECURITY.value else "Identity Governance"
        time_str = (asmt.timestamp[:19].replace("T", " ") + " UTC") if asmt else req.created_at[:19].replace("T", " ")

        if asmt:
            verdict_badge = render_verdict_badge(asmt.verdict)
            score_badge = render_risk_score_badge(asmt.composite_risk_score)
            status_line = (
                f"Score: <strong>{asmt.composite_risk_score:.1f}/100</strong> • "
                f"Gaps: <strong>{asmt.security_gaps_count}</strong> "
                f"(<span style='color:#ef4444;'>{asmt.critical_count} Crit</span>, "
                f"<span style='color:#f97316;'>{asmt.high_count} High</span>, "
                f"<span style='color:#eab308;'>{asmt.medium_count} Med</span>) • "
                f"Blast Radius: <strong>{asmt.blast_radius_nodes_count} Assets</strong>"
            )
        else:
            verdict_badge = '<span class="sg-badge sg-badge-neutral">PENDING SIMULATION</span>'
            score_badge = '<span class="sg-badge sg-badge-neutral">N/A</span>'
            status_line = "<span style='color:#64748b;'>Simulation has not been executed for this change request.</span>"

        # Card container
        st.markdown(
            f"""
            <div class="sg-card" style="margin-bottom: 1rem;">
                <div class="sg-card-header">
                    <div>
                        <span style="font-family:monospace; font-weight:700; color:#0f62fe; font-size:1rem; margin-right:8px;">
                            {html.escape(req_no)}
                        </span>
                        <span style="font-weight:600; color:#1e293b; font-size:0.95rem;">
                            {html.escape(req.title)}
                        </span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        {verdict_badge}
                        {score_badge}
                    </div>
                </div>

                <div style="display:flex; flex-wrap:wrap; gap:1.5rem; font-size:0.83rem; color:#475569; margin-bottom:0.75rem;">
                    <div>CI: <strong>{html.escape(req.configuration_item or 'None')}</strong></div>
                    <div>Domain: <strong>{domain_label}</strong></div>
                    <div>Submitter: <strong>{html.escape(req.submitted_by)}</strong></div>
                    <div>Priority: <strong>{html.escape(req.priority)}</strong></div>
                    <div>Timestamp: <strong>{time_str}</strong></div>
                </div>

                <div style="font-size:0.84rem; color:#334155; background:#f8fafc; border:1px solid #e2e8f0; border-radius:4px; padding:6px 10px; margin-bottom:0.75rem;">
                    {status_line}
                </div>
            """,
            unsafe_allow_html=True,
        )

        # Action and Download Row
        col_btn1, col_btn2, col_btn3, col_btn4 = st.columns([1.5, 1.5, 1.2, 1.2])

        if asmt:
            # Generate exports lazily for download buttons
            pdf_bytes = build_executive_pdf(
                request_record=req,
                assessment_record=asmt,
                remediation_record=rem,
            )
            json_str = build_executive_json(
                request_record=req,
                assessment_record=asmt,
                remediation_record=rem,
            )

            pdf_filename = get_safe_export_filename(req_no, asmt.assessment_id, "pdf")
            json_filename = get_safe_export_filename(req_no, asmt.assessment_id, "json")

            with col_btn1:
                st.download_button(
                    label="📄 Download Executive PDF",
                    data=pdf_bytes,
                    file_name=pdf_filename,
                    mime="application/pdf",
                    key=f"btn_pdf_{req_no}_{asmt.assessment_id}",
                    use_container_width=True,
                )

            with col_btn2:
                st.download_button(
                    label="{ } Download Audit JSON",
                    data=json_str,
                    file_name=json_filename,
                    mime="application/json",
                    key=f"btn_json_{req_no}_{asmt.assessment_id}",
                    use_container_width=True,
                )

            with col_btn3:
                if st.button("📊 View Results", key=f"btn_res_{req_no}", use_container_width=True):
                    st.session_state["viewing_request_number"] = req_no
                    st.session_state["active_page"] = PAGE_RESULTS
                    st.rerun()

            with col_btn4:
                if st.button("📋 Change Detail", key=f"btn_det_{req_no}", use_container_width=True):
                    st.session_state["viewing_request_number"] = req_no
                    st.session_state["active_page"] = "Record Detail"
                    st.rerun()
        else:
            with col_btn1:
                if st.button("🚀 Run Pre-Flight Simulation", key=f"btn_run_{req_no}", use_container_width=True):
                    st.session_state["viewing_request_number"] = req_no
                    st.session_state["active_page"] = PAGE_RESULTS
                    st.rerun()

            with col_btn2:
                st.button("📄 PDF Export Unavailable", disabled=True, key=f"btn_dis_pdf_{req_no}", use_container_width=True)

            with col_btn3:
                st.button("{ } JSON Unavailable", disabled=True, key=f"btn_dis_json_{req_no}", use_container_width=True)

            with col_btn4:
                if st.button("📋 Change Detail", key=f"btn_det_{req_no}", use_container_width=True):
                    st.session_state["viewing_request_number"] = req_no
                    st.session_state["active_page"] = "Record Detail"
                    st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

"""Before & After Validation Comparison Page — differential verification of risk reduction."""

import json
from typing import Optional
import streamlit as st

from config.settings import PAGE_REMEDIATION, PAGE_RESULTS
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_metric_card
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header


def render_comparison_page(repository: ChangeRepository) -> None:
    """Render the Before-and-After differential comparison view."""
    render_page_header(
        title="Before & After Validation Comparison",
        description="Closed-loop verification of risk reduction, finding resolution tracking, and blast-radius contraction.",
    )

    active_req_no = st.session_state.get("viewing_request_number")
    all_requests = repository.list_change_requests(limit=50)

    if not all_requests:
        st.markdown(
            """
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">⚖️</div>
                <div class="sg-empty-title">No Change Requests Found</div>
                <div class="sg-empty-subtitle">Submit a Change Request and run pre-flight simulation first.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    req_options = [r.request_number for r in all_requests]
    current_idx = req_options.index(active_req_no) if active_req_no in req_options else 0

    col_sel1, col_sel2 = st.columns([3, 1])
    with col_sel1:
        selected_req_no = st.selectbox(
            "Select Change Request to Compare",
            options=req_options,
            index=current_idx,
            format_func=lambda x: f"{x} — {next((r.title for r in all_requests if r.request_number == x), '')}",
            key="comparison_req_selector",
        )
        st.session_state["viewing_request_number"] = selected_req_no

    with col_sel2:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🛠️ Remediation Plan →", use_container_width=True, key="btn_nav_to_rem_from_comp"):
            st.session_state["active_page"] = PAGE_REMEDIATION
            st.rerun()

    # Load records
    record = repository.get_change_request(selected_req_no)
    orig_asmt = repository.get_latest_assessment(selected_req_no, assessment_type="ORIGINAL")
    post_asmt = repository.get_latest_assessment(selected_req_no, assessment_type="POST_REMEDIATION")
    rem_record = repository.get_remediation_record(selected_req_no)

    if not orig_asmt:
        st.markdown(
            f"""
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">⚖️</div>
                <div class="sg-empty-title">No Baseline Simulation for {selected_req_no}</div>
                <div class="sg-empty-subtitle">Execute an initial security assessment to generate baseline metrics.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Check for comparison JSON
    comp_data = {}
    if rem_record and rem_record.comparison_json:
        try:
            comp_data = json.loads(rem_record.comparison_json)
        except Exception:
            pass

    score_before = orig_asmt.composite_risk_score
    score_after = post_asmt.composite_risk_score if post_asmt else (score_before if not comp_data else comp_data.get("risk_score_after", 0.0))
    delta = int(round(score_before - score_after))

    verdict_before = orig_asmt.verdict
    verdict_after = post_asmt.verdict if post_asmt else (comp_data.get("verdict_after", "ALLOW"))

    resolved_cnt = comp_data.get("resolved_count", 0)
    partially_cnt = comp_data.get("partially_resolved_count", 0)
    unresolved_cnt = comp_data.get("unresolved_count", 0)
    regression_cnt = comp_data.get("regression_count", 0)
    manual_cnt = comp_data.get("manual_review_count", 0)

    # 1. Delta & Resolution Metrics Row
    col_k1, col_k2, col_k3, col_k4, col_k5 = st.columns(5)
    with col_k1:
        render_metric_card(
            label="Baseline Risk",
            value=f"{score_before:.1f} / 100",
            hint=f"Verdict: {verdict_before}",
        )
    with col_k2:
        render_metric_card(
            label="Candidate Risk",
            value=f"{score_after:.1f} / 100",
            hint=f"Verdict: {verdict_after}",
        )
    with col_k3:
        render_metric_card(
            label="Risk Reduction Delta",
            value=f"-{delta} Points",
            hint="Deterministic score decrease",
        )
    with col_k4:
        render_metric_card(
            label="Resolved / Partial",
            value=f"{resolved_cnt} / {partially_cnt}",
            hint="Gaps eliminated",
        )
    with col_k5:
        render_metric_card(
            label="Residual Manual Reviews",
            value=f"{manual_cnt}",
            hint="Operational confirmations",
        )

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 2. Verdict Transition Card
    v_badge_before = render_verdict_badge(verdict_before)
    v_badge_after = render_verdict_badge(verdict_after)

    st.markdown(
        f"""
        <div class="sg-card">
            <div class="sg-card-header">
                <span>Gate Verdict Transition</span>
                <span class="sg-badge sg-badge-info">Closed-Loop Validation Outcome</span>
            </div>
            <div style="display:flex; justify-content:space-around; align-items:center; padding:1.25rem 0;">
                <div style="text-align:center;">
                    <div style="font-size:0.8rem; color:#64748b; margin-bottom:4px; text-transform:uppercase;">Original Policy Verdict</div>
                    <div>{v_badge_before}</div>
                    <div style="font-size:1.1rem; font-weight:700; color:#ef4444; margin-top:4px;">Risk: {score_before:.1f}</div>
                </div>
                <div style="font-size:2rem; color:#94a3b8; font-weight:300;">➔</div>
                <div style="text-align:center;">
                    <div style="font-size:0.8rem; color:#64748b; margin-bottom:4px; text-transform:uppercase;">Remediated Policy Verdict</div>
                    <div>{v_badge_after}</div>
                    <div style="font-size:1.1rem; font-weight:700; color:#10b981; margin-top:4px;">Risk: {score_after:.1f}</div>
                </div>
            </div>
            <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:0.75rem 1rem; font-size:0.85rem; color:#475569;">
                <strong>Validation Principle:</strong> A lower risk score does not automatically mean the candidate is safe to deploy.
                Residual findings, rule shadowing, or unmapped dependencies require explicit operational confirmation.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Finding Resolution Matrix
    st.markdown(
        """
        <div class="sg-card">
            <div class="sg-card-header">
                <span>Finding Resolution Tracking Matrix</span>
                <span style="font-size:0.78rem; color:#64748b;">Differential Gap Analysis</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    finding_resolutions = comp_data.get("finding_resolutions", [])
    if finding_resolutions:
        table_rows = []
        for f in finding_resolutions:
            ident = f.get("finding_identity", {})
            rule = ident.get("rule_id", "GAP")
            res_name = ident.get("affected_resource", "")
            title = f.get("original_gap_title", "")
            status = f.get("resolution_status", "RESOLVED")
            evidence = f.get("validation_evidence", "")

            if status == "RESOLVED":
                badge = '<span class="sg-badge sg-badge-allow">RESOLVED</span>'
            elif status == "PARTIALLY_RESOLVED":
                badge = '<span class="sg-badge sg-badge-warn">PARTIALLY RESOLVED</span>'
            elif status == "REGRESSION_INTRODUCED":
                badge = '<span class="sg-badge sg-badge-block">REGRESSION INTRODUCED</span>'
            elif status == "NEEDS_MANUAL_REVIEW":
                badge = '<span class="sg-badge sg-badge-warn">MANUAL REVIEW</span>'
            else:
                badge = '<span class="sg-badge sg-badge-neutral">UNRESOLVED</span>'

            table_rows.append(
                f"""
                <tr style="border-bottom:1px solid #f1f5f9;">
                    <td style="font-family:monospace; font-weight:700; color:#0f62fe; padding:8px;">{rule}</td>
                    <td style="font-weight:600; padding:8px;">{title}</td>
                    <td style="padding:8px;"><code>{res_name}</code></td>
                    <td style="padding:8px;">{badge}</td>
                    <td style="font-size:0.82rem; color:#475569; padding:8px;">{evidence}</td>
                </tr>
                """
            )

        st.markdown(
            f"""
            <table style="width:100%; border-collapse:collapse; font-size:0.85rem; text-align:left;">
                <thead>
                    <tr style="border-bottom:2px solid #e2e8f0; color:#475569; font-size:0.75rem; text-transform:uppercase;">
                        <th style="padding:8px;">Rule ID</th>
                        <th style="padding:8px;">Original Finding</th>
                        <th style="padding:8px;">Resource</th>
                        <th style="padding:8px;">Resolution Status</th>
                        <th style="padding:8px;">Validation Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(table_rows)}
                </tbody>
            </table>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.info("Differential finding resolution details will populate when candidate remediation is validated.")

    st.markdown("</div>", unsafe_allow_html=True)

    # 4. Blast-Radius Contraction Summary
    direct_before = comp_data.get("direct_assets_before", orig_asmt.blast_radius_nodes_count)
    direct_after = comp_data.get("direct_assets_after", (post_asmt.blast_radius_nodes_count if post_asmt else 0))
    casc_before = comp_data.get("cascading_assets_before", 0)
    casc_after = comp_data.get("cascading_assets_after", 0)

    col_br1, col_br2 = st.columns(2)
    with col_br1:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">Direct Assets Reached</div>
                <div style="font-size:1.8rem; font-weight:700; color:#0f172a;">
                    {direct_before} <span style="font-size:1rem; color:#94a3b8; font-weight:400;">→</span> {direct_after}
                </div>
                <div style="font-size:0.82rem; color:#15803d; margin-top:4px;">
                    Contraction: {max(0, direct_before - direct_after)} asset(s) severed from exposure path
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_br2:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">Cascading Dependencies Affected</div>
                <div style="font-size:1.8rem; font-weight:700; color:#0f172a;">
                    {casc_before} <span style="font-size:1rem; color:#94a3b8; font-weight:400;">→</span> {casc_after}
                </div>
                <div style="font-size:0.82rem; color:#15803d; margin-top:4px;">
                    Contraction: {max(0, casc_before - casc_after)} downstream dependencies shielded
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

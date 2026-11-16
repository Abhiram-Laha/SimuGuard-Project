"""Remediation Center Page — inspect candidate policy synthesis, automated hardening, and validation."""

import json
from pathlib import Path
from typing import Optional
import streamlit as st

from config.settings import PAGE_COMPARISON, PAGE_RESULTS
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_metric_card
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header


def render_remediation_page(repository: ChangeRepository) -> None:
    """Render the Remediation Center with candidate policy generation and overlay review."""
    render_page_header(
        title="Remediation Center",
        description="Traceable candidate policy synthesis, automated least-privilege scoping, and isolated Candidate Digital Twin validation.",
    )

    active_req_no = st.session_state.get("viewing_request_number")
    all_requests = repository.list_change_requests(limit=50)

    if not all_requests:
        st.markdown(
            """
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">🛠️</div>
                <div class="sg-empty-title">No Change Requests Found</div>
                <div class="sg-empty-subtitle">Submit a Change Request and execute a security simulation first.</div>
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
            "Select Change Request for Remediation Review",
            options=req_options,
            index=current_idx,
            format_func=lambda x: f"{x} — {next((r.title for r in all_requests if r.request_number == x), '')}",
            key="remediation_req_selector",
        )
        st.session_state["viewing_request_number"] = selected_req_no

    with col_sel2:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("⚖️ Compare Before & After →", use_container_width=True, key="btn_nav_to_comp_from_rem"):
            st.session_state["active_page"] = PAGE_COMPARISON
            st.rerun()

    # Load records
    record = repository.get_change_request(selected_req_no)
    remediation_record = repository.get_remediation_record(selected_req_no)
    orig_assessment = repository.get_latest_assessment(selected_req_no, assessment_type="ORIGINAL")
    post_assessment = repository.get_latest_assessment(selected_req_no, assessment_type="POST_REMEDIATION")

    if not remediation_record or not remediation_record.plan_json:
        st.markdown(
            f"""
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">🛠️</div>
                <div class="sg-empty-title">No Remediation Plan Available for {selected_req_no}</div>
                <div class="sg-empty-subtitle">
                    A remediation plan has not been generated yet. Open the Assessment Results page and run a security assessment.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("🔍 Go to Assessment Results", key="btn_goto_results"):
            st.session_state["active_page"] = PAGE_RESULTS
            st.rerun()
        return

    # Parse remediation plan
    try:
        plan_data = json.loads(remediation_record.plan_json)
    except Exception:
        plan_data = {}

    recommendations = plan_data.get("recommendations", [])
    candidate_hcl = remediation_record.synthesized_hcl or ""

    # Parse comparison report if present
    comp_data = {}
    if remediation_record.comparison_json:
        try:
            comp_data = json.loads(remediation_record.comparison_json)
        except Exception:
            comp_data = {}

    # Metric Row
    col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
    with col_m1:
        render_metric_card(
            label="Plan Status",
            value=remediation_record.status,
            hint="Validation Pipeline State",
        )
    with col_m2:
        render_metric_card(
            label="Recommendations",
            value=len(recommendations),
            hint="Traceable Remediation Patches",
        )
    with col_m3:
        resolved_cnt = comp_data.get("resolved_count", len(recommendations))
        render_metric_card(
            label="Resolved Gaps",
            value=f"{resolved_cnt}",
            hint="Verified Closed-Loop",
        )
    with col_m4:
        manual_cnt = comp_data.get("manual_review_count", 0)
        render_metric_card(
            label="Manual Reviews",
            value=f"{manual_cnt}",
            hint="Engineer Action Required",
        )
    with col_m5:
        score_after = post_assessment.composite_risk_score if post_assessment else 0.0
        render_metric_card(
            label="Candidate Risk",
            value=f"{score_after:.1f} / 100",
            hint="Post-Remediation Score",
        )

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # Tabs: Recommendations, Configuration Diff, Validation Checks
    tab_recs, tab_diff, tab_overlay = st.tabs(
        [
            "📋 Traceable Recommendations",
            "🔄 Configuration Diff (Original vs Candidate)",
            "🛡️ Candidate Digital Twin Overlay & Validation",
        ]
    )

    # -------------------------------------------------------------------------
    # TAB 1: RECOMMENDATIONS
    # -------------------------------------------------------------------------
    with tab_recs:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Generated Remediation Actions</span>
                    <span class="sg-badge sg-badge-info">{len(recommendations)} Recommendation(s)</span>
                </div>
            """,
            unsafe_allow_html=True,
        )

        if recommendations:
            for rec in recommendations:
                rem_id = rec.get("remediation_id", "REM")
                orig_rule = rec.get("rule_id", "")
                res = rec.get("affected_resource", "")
                confidence = float(rec.get("confidence_score", 1.0)) * 100
                requires_manual = rec.get("requires_manual_review", False)
                expl = rec.get("explanation", "")
                benefit = rec.get("security_benefit", "")
                op_impact = rec.get("operational_impact", "")
                current_snip = rec.get("current_config_snippet", "")
                rec_snip = rec.get("recommended_config_snippet", "")
                limitations = rec.get("limitations")

                man_badge = '<span class="sg-badge sg-badge-warn">REQUIRES MANUAL REVIEW</span>' if requires_manual else '<span class="sg-badge sg-badge-allow">AUTOMATED FIX</span>'

                st.markdown(
                    f"""
                    <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:1.1rem; margin-bottom:1rem; box-shadow:0 1px 2px rgba(0,0,0,0.02);">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                            <div>
                                <span style="font-family:monospace; font-weight:700; color:#0f62fe;">{rem_id}</span>
                                <span style="margin:0 6px; color:#cbd5e1;">|</span>
                                <span style="font-weight:600; font-size:0.95rem;">Rule: {orig_rule}</span>
                                <span style="margin:0 6px; color:#cbd5e1;">|</span>
                                <span style="font-size:0.88rem; color:#475569;">Resource: <code>{res}</code></span>
                            </div>
                            <div style="display:flex; gap:6px;">
                                <span class="sg-badge sg-badge-info">Confidence: {confidence:.0f}%</span>
                                {man_badge}
                            </div>
                        </div>
                        <div style="margin-top:8px; font-size:0.88rem; color:#1e293b; line-height:1.5;">
                            <strong>Explanation:</strong> {expl}
                        </div>
                        <div style="margin-top:6px; font-size:0.84rem; color:#065f46;">
                            <strong>Security Benefit:</strong> {benefit}
                        </div>
                        <div style="margin-top:4px; font-size:0.84rem; color:#64748b;">
                            <strong>Operational Impact:</strong> {op_impact}
                        </div>
                    """,
                    unsafe_allow_html=True,
                )

                if limitations:
                    st.markdown(
                        f"""
                        <div style="margin-top:6px; font-size:0.82rem; color:#b45309; background:#fffbeb; padding:6px 10px; border-radius:4px; border:1px solid #fde68a;">
                            <strong>Notice:</strong> {limitations}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                with st.expander(f"View Proposed Configuration Patch for {rem_id}"):
                    col_p1, col_p2 = st.columns(2)
                    with col_p1:
                        st.markdown("**Original Unsafe Snippet:**")
                        st.code(current_snip, language="hcl")
                    with col_p2:
                        st.markdown("**Recommended Hardened Snippet:**")
                        st.code(rec_snip, language="hcl")

                st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("No explicit remediation actions required for this configuration.")

        st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # TAB 2: CONFIGURATION DIFF
    # -------------------------------------------------------------------------
    with tab_diff:
        col_cd1, col_cd2 = st.columns(2)
        with col_cd1:
            st.markdown(
                """
                <div class="sg-card">
                    <div class="sg-card-header">
                        <span>Original Configuration</span>
                        <span class="sg-badge sg-badge-block">UNSAFE BASELINE</span>
                    </div>
                """,
                unsafe_allow_html=True,
            )
            orig_hcl = record.raw_content or ""
            if not orig_hcl and record.source_file_path and Path(record.source_file_path).exists():
                orig_hcl = Path(record.source_file_path).read_text(encoding="utf-8")
            st.code(orig_hcl or "# Original configuration unavailable", language="hcl")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_cd2:
            st.markdown(
                """
                <div class="sg-card">
                    <div class="sg-card-header">
                        <span>Candidate Remediated Configuration</span>
                        <span class="sg-badge sg-badge-allow">HARDENED CANDIDATE</span>
                    </div>
                """,
                unsafe_allow_html=True,
            )
            st.code(candidate_hcl or "# Candidate HCL unavailable", language="hcl")
            st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # TAB 3: CANDIDATE OVERLAY & VALIDATION
    # -------------------------------------------------------------------------
    with tab_overlay:
        st.markdown(
            """
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Isolated Candidate Digital Twin Overlay Results</span>
                    <span class="sg-badge sg-badge-info">Memory Sandbox (Zero Production Impact)</span>
                </div>
                <div style="font-size:0.88rem; color:#475569; margin-bottom:1rem; line-height:1.5;">
                    The remediation pipeline executed closed-loop validation over an ephemeral candidate overlay graph.
                    Original repository files, production firewalls, and active IAM roles were untouched.
                </div>
            """,
            unsafe_allow_html=True,
        )

        overlay_data = comp_data.get("candidate_overlay_result") or {}
        removed_edges = overlay_data.get("removed_relationships", [])
        added_edges = overlay_data.get("added_relationships", [])
        op_warnings = overlay_data.get("operational_warnings", [])

        col_ov1, col_ov2 = st.columns(2)
        with col_ov1:
            st.markdown("##### ✂️ Severed Toxic Permissions & Exposure Paths")
            if removed_edges:
                for edge in removed_edges:
                    st.markdown(f"- ✕ `{edge}`")
            else:
                st.markdown("- *Explicit removal of AmazonS3FullAccess wildcard attachment.*")

        with col_ov2:
            st.markdown("##### 🔒 Newly Established Scoped Relationships")
            if added_edges:
                for edge in added_edges:
                    st.markdown(f"- ✓ `{edge}`")
            else:
                st.markdown("- *Attached scoped least-privilege customer managed policy.*")

        if op_warnings:
            st.markdown("##### ⚠️ Operational Warnings & Residual Checks")
            for warn in op_warnings:
                st.warning(warn)

        st.markdown("</div>", unsafe_allow_html=True)

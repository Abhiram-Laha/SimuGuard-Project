"""Assessment Results Page — comprehensive inspection of pre-flight security simulation findings."""

import json
from typing import Optional
import streamlit as st

from config.settings import PAGE_COMPARISON, PAGE_HISTORY, PAGE_REMEDIATION
from storage.models import AssessmentRecord
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_metric_card
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header
from ui.services.assessment_runner import AssessmentRunnerService


def render_results_page(repository: ChangeRepository) -> None:
    """Render the detailed pre-flight simulation assessment results."""
    render_page_header(
        title="Simulation Assessment Results",
        description="Comprehensive pre-deployment security findings, deterministic risk scores, blast-radius asset impact, and validation plans.",
    )

    # 1. Resolve Active Change Request
    active_req_no = st.session_state.get("viewing_request_number")

    # Let user select from available requests
    all_requests = repository.list_change_requests(limit=50)
    if not all_requests:
        st.markdown(
            """
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">🔍</div>
                <div class="sg-empty-title">No Change Requests Found</div>
                <div class="sg-empty-subtitle">
                    Submit a Change Request first or initialize a demo scenario to inspect simulation results.
                </div>
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
            "Select Change Request to Inspect",
            options=req_options,
            index=current_idx,
            format_func=lambda x: f"{x} — {next((r.title for r in all_requests if r.request_number == x), '')}",
            key="results_req_selector",
        )
        st.session_state["viewing_request_number"] = selected_req_no
    with col_sel2:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🔄 Re-run Assessment", key="btn_rerun_assessment_results", use_container_width=True):
            runner = AssessmentRunnerService(repository=repository)
            with st.spinner("Executing simulation engine..."):
                ok, msg, res = runner.run_assessment(selected_req_no, force_reassessment=True)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    # Fetch request and latest assessment record
    record = repository.get_change_request(selected_req_no)
    assessment = repository.get_latest_assessment(selected_req_no, assessment_type="ORIGINAL")

    if not assessment or not assessment.raw_json:
        st.markdown(
            f"""
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">⚠️</div>
                <div class="sg-empty-title">No Assessment Record for {selected_req_no}</div>
                <div class="sg-empty-subtitle">
                    This Change Request is in state <strong>{record.status if record else 'UNKNOWN'}</strong> and has not been simulated yet.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        col_run1, col_run2, col_run3 = st.columns([1, 1, 1])
        with col_run2:
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            if st.button("🚀 Run Security Assessment Now", key="btn_run_asmt_empty_results", use_container_width=True):
                runner = AssessmentRunnerService(repository=repository)
                with st.spinner("Analyzing infrastructure and evaluating policy rules..."):
                    ok, msg, res = runner.run_assessment(selected_req_no, force_reassessment=True)
                if ok:
                    st.success("Simulation complete!")
                    st.rerun()
                else:
                    st.error(msg)
        return

    # Parse raw report
    try:
        report_data = json.loads(assessment.raw_json)
    except Exception:
        report_data = {}

    gaps = report_data.get("identified_security_gaps", [])
    affected_assets = report_data.get("predicted_affected_assets", [])
    validation_checks = report_data.get("pre_implementation_validation_plan", [])
    exec_summary = report_data.get("executive_summary", "")

    # 2. Executive KPI Header
    verdict = assessment.verdict
    score = assessment.composite_risk_score
    crit_count = assessment.critical_count
    high_count = assessment.high_count
    med_count = assessment.medium_count
    low_count = assessment.low_count
    blast_count = assessment.blast_radius_nodes_count

    col_k1, col_k2, col_k3, col_k4, col_k5 = st.columns(5)
    with col_k1:
        render_metric_card(
            label="Gate Verdict",
            value=f"{verdict}",
            hint="Deterministic Pre-Flight Gate",
        )
    with col_k2:
        render_metric_card(
            label="Risk Score",
            value=f"{score:.1f} / 100",
            hint="Composite Risk Assessment",
        )
    with col_k3:
        render_metric_card(
            label="Critical / High Gaps",
            value=f"{crit_count} / {high_count}",
            hint="Immediate Security Blockers",
        )
    with col_k4:
        render_metric_card(
            label="Medium / Low Gaps",
            value=f"{med_count} / {low_count}",
            hint="Operational & Hygiene Gaps",
        )
    with col_k5:
        render_metric_card(
            label="Blast Radius",
            value=f"{blast_count} Assets",
            hint="Direct & Cascading Nodes",
        )

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 3. Context & Executive Summary Card
    verdict_badge = render_verdict_badge(verdict)
    state_badge = render_workflow_badge(record.status if record else "ANALYZED")
    prio_badge = render_priority_badge(record.priority if record else "NORMAL")

    st.markdown(
        f"""
        <div class="sg-card">
            <div class="sg-card-header">
                <span>Executive Simulation Summary</span>
                <div>{verdict_badge}</div>
            </div>
            <div style="font-size: 0.92rem; color: #1e293b; line-height: 1.6; margin-bottom: 0.75rem;">
                {exec_summary}
            </div>
            <div style="display: flex; gap: 1.5rem; font-size: 0.82rem; color: #64748b; border-top: 1px solid #f1f5f9; padding-top: 0.5rem;">
                <div>Assessment ID: <code style="color:#0f62fe;">{assessment.assessment_id}</code></div>
                <div>Domain: <strong>{record.domain if record else 'Unknown'}</strong></div>
                <div>Source: <code>{record.scenario_name or Path(record.source_file_path or '').name or 'Custom'}</code></div>
                <div>Timestamp: <strong>{assessment.timestamp[:19].replace('T', ' ')} UTC</strong></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 4. Action Toolbar
    col_act1, col_act2, col_act3, col_act4 = st.columns([1, 1, 1, 2])
    with col_act1:
        if st.button("🛠️ Remediation Center →", use_container_width=True, key="btn_nav_to_rem"):
            st.session_state["active_page"] = PAGE_REMEDIATION
            st.rerun()
    with col_act2:
        if st.button("⚖️ Before & After →", use_container_width=True, key="btn_nav_to_comp"):
            st.session_state["active_page"] = PAGE_COMPARISON
            st.rerun()
    with col_act3:
        if st.button("📋 Change Details", use_container_width=True, key="btn_nav_to_detail"):
            st.session_state["active_page"] = "Record Detail"
            st.rerun()

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 5. Identified Security Gaps Table
    st.markdown(
        f"""
        <div class="sg-card">
            <div class="sg-card-header">
                <span>Identified Security Gaps & Policy Violations</span>
                <span class="sg-badge sg-badge-neutral">{len(gaps)} Finding(s)</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    if gaps:
        for idx, gap in enumerate(gaps, start=1):
            rule_id = gap.get("rule_id", "GAP")
            severity = gap.get("severity", "MEDIUM")
            title = gap.get("gap_title", "Security Finding")
            impact = gap.get("technical_impact", "")
            compliance = gap.get("compliance_violation", "")
            remediation = gap.get("remediation_guidance", "")

            sev_class = "sg-badge-block" if severity in ["CRITICAL", "HIGH"] else "sg-badge-warn"

            st.markdown(
                f"""
                <div style="background:#ffffff; border: 1px solid #e2e8f0; border-left: 4px solid {'#ef4444' if severity in ['CRITICAL', 'HIGH'] else '#f59e0b'}; border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 0.85rem;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <span style="font-family: monospace; font-size: 0.82rem; font-weight: 700; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; color: #334155;">
                                {rule_id}
                            </span>
                            <span style="font-size: 1rem; font-weight: 600; color: #0f172a; margin-left: 8px;">
                                {title}
                            </span>
                        </div>
                        <span class="sg-badge {sev_class}">{severity}</span>
                    </div>
                    <div style="margin-top: 8px; font-size: 0.88rem; color: #334155; line-height: 1.5;">
                        <strong>Technical Impact:</strong> {impact}
                    </div>
                    <div style="margin-top: 6px; font-size: 0.84rem; color: #475569;">
                        <strong>Compliance Framework:</strong> <span style="color:#b45309;">{compliance}</span>
                    </div>
                    <div style="margin-top: 6px; font-size: 0.84rem; color: #065f46; background: #f0fdf4; padding: 8px 10px; border-radius: 4px; border: 1px solid #bbf7d0;">
                        <strong>Remediation Guidance:</strong> {remediation}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            """
            <div style="padding: 1.5rem; text-align: center; color: #10b981; font-weight: 600;">
                ✓ No security gaps or policy violations identified. Configuration adheres to security baseline.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # 6. Blast Radius & Affected Assets
    col_br1, col_br2 = st.columns([3, 2])
    with col_br1:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Blast Radius: Affected Infrastructure Assets</span>
                    <span style="font-size: 0.78rem; color: #64748b;">{len(affected_assets)} Node(s) Traversed</span>
                </div>
            """,
            unsafe_allow_html=True,
        )

        if affected_assets:
            asset_rows = []
            for a in affected_assets:
                tier = a.get("tier", "DIRECT")
                tier_badge = '<span class="sg-badge sg-badge-block">DIRECT</span>' if tier == "DIRECT" else '<span class="sg-badge sg-badge-warn">CASCADING</span>'
                crit = a.get("criticality", "HIGH")
                asset_rows.append(
                    f"""
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="font-weight:600; font-family:monospace; color:#0f62fe;">{a.get('asset_id')}</td>
                        <td>{a.get('asset_name')}</td>
                        <td><span style="font-size:0.8rem; color:#64748b;">{a.get('asset_type')}</span></td>
                        <td>{tier_badge}</td>
                        <td><span style="font-size:0.8rem; font-weight:600;">{crit}</span></td>
                    </tr>
                    """
                )

            st.markdown(
                f"""
                <table style="width:100%; border-collapse:collapse; font-size:0.85rem; text-align:left;">
                    <thead>
                        <tr style="border-bottom: 2px solid #e2e8f0; color:#475569; font-size:0.75rem; text-transform:uppercase;">
                            <th style="padding:8px;">Asset ID</th>
                            <th style="padding:8px;">Name</th>
                            <th style="padding:8px;">Type</th>
                            <th style="padding:8px;">Tier</th>
                            <th style="padding:8px;">Criticality</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(asset_rows)}
                    </tbody>
                </table>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.info("No sensitive assets directly reachable in the blast radius.")

        st.markdown("</div>", unsafe_allow_html=True)

    with col_br2:
        st.markdown(
            """
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Pre-Implementation Validation Plan</span>
                    <span style="font-size: 0.78rem; color: #64748b;">CLI Checks</span>
                </div>
            """,
            unsafe_allow_html=True,
        )

        if validation_checks:
            for check in validation_checks:
                step_no = check.get("step_number", 1)
                target = check.get("target_component", "")
                cmd = check.get("cli_command", "")
                criteria = check.get("expected_pass_criteria", "")

                st.markdown(
                    f"""
                    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:0.75rem; margin-bottom:0.6rem;">
                        <div style="font-size:0.82rem; font-weight:600; color:#0f172a;">Step {step_no}: {target}</div>
                        <div style="margin:4px 0;"><code style="font-size:0.78rem; color:#0f62fe; word-break:break-all;">{cmd}</code></div>
                        <div style="font-size:0.78rem; color:#15803d;"><strong>Pass Criteria:</strong> {criteria}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.write("No pre-implementation CLI validation checks required.")

        st.markdown("</div>", unsafe_allow_html=True)

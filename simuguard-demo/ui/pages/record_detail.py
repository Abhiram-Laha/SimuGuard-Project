"""Change Request Record Detail Page — ServiceNow-inspired view with structured tabs and activity audit timeline."""

import json
from pathlib import Path
from typing import Optional
import streamlit as st

from config.settings import PAGE_HISTORY
from storage.models import WorkflowState
from storage.repository import ChangeRepository
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header


def render_record_detail_page(repository: ChangeRepository, request_number: Optional[str] = None) -> None:
    """Render the comprehensive record detail view for a specific Change Request."""
    req_no = request_number or st.session_state.get("viewing_request_number")
    if not req_no:
        st.error("No Change Request identifier specified.")
        if st.button("← Back to History"):
            st.session_state["active_page"] = PAGE_HISTORY
            st.rerun()
        return

    record = repository.get_change_request(req_no)
    if not record:
        st.error(f"Change Request '{req_no}' not found in local database.")
        if st.button("← Back to History"):
            st.session_state["active_page"] = PAGE_HISTORY
            st.rerun()
        return

    latest_assessment = repository.get_latest_assessment(req_no)

    # 1. Record Header
    state_badge = render_workflow_badge(record.status)
    prio_badge = render_priority_badge(record.priority)
    verdict_badge = (
        render_verdict_badge(latest_assessment.verdict)
        if latest_assessment
        else '<span class="sg-badge sg-badge-neutral">UNASSESSED (PENDING SIMULATION)</span>'
    )
    score_badge = (
        render_risk_score_badge(latest_assessment.composite_risk_score)
        if latest_assessment
        else '<span style="color:#94a3b8; font-weight:600;">-</span>'
    )

    col_h1, col_h2 = st.columns([4, 1])
    with col_h1:
        st.markdown(
            f"""
            <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="font-size: 0.8rem; text-transform: uppercase; color: #64748b; font-weight: 600; letter-spacing: 0.04em;">
                            Apex Global ITSM Change Management • Record Details
                        </div>
                        <h1 style="font-size: 1.6rem; font-weight: 700; color: #0f172a; margin: 4px 0;">
                            <span style="color: #0f62fe; font-family: monospace;">{record.request_number}</span> — {record.title}
                        </h1>
                        <div style="font-size: 0.88rem; color: #475569; margin-top: 4px;">
                            <span>Requested By: <strong>{record.submitted_by}</strong></span>
                            <span style="margin: 0 8px;">•</span>
                            <span>Assigned Group: <strong>{record.assignment_group}</strong></span>
                            <span style="margin: 0 8px;">•</span>
                            <span>Created: <strong>{record.created_at[:19].replace('T', ' ')} UTC</strong></span>
                        </div>
                    </div>
                    <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 6px;">
                        <div style="display: flex; gap: 6px;">
                            {prio_badge}
                            {state_badge}
                        </div>
                        <div style="margin-top: 4px;">
                            {verdict_badge}
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_h2:
        if st.button("← Back to History", use_container_width=True):
            st.session_state["active_page"] = PAGE_HISTORY
            st.rerun()

        if record.status == WorkflowState.DRAFT.value:
            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            if st.button("🚀 Submit Draft", use_container_width=True):
                repository.submit_change_request(record)
                st.success(f"Change Request {record.request_number} promoted to SUBMITTED status.")
                st.rerun()

    # 2. Structured Tabs
    tab_overview, tab_desc, tab_ci, tab_plan, tab_sched, tab_risk, tab_activity = st.tabs(
        [
            "📊 Overview",
            "📝 Description & Justification",
            "🧩 Configuration & Domain",
            "🛠️ Planning & Validation",
            "📅 Schedule",
            "⚠️ Initial Risk Context",
            "📜 Activity Timeline",
        ]
    )

    # -------------------------------------------------------------------------
    # TAB 1: OVERVIEW
    # -------------------------------------------------------------------------
    with tab_overview:
        col_ov1, col_ov2 = st.columns(2)
        with col_ov1:
            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">ITSM Classification</div>
                    <table style="width:100%; font-size:0.88rem;">
                        <tr><td style="color:#64748b; padding:6px 0;">Request Number:</td><td style="font-weight:600; font-family:monospace;">{record.request_number}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Change Type:</td><td><strong>{record.change_type}</strong></td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Category:</td><td>{record.category}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Subcategory:</td><td>{record.subcategory}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Priority:</td><td>{prio_badge}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Status:</td><td>{state_badge}</td></tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_ov2:
            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">Assignment & Ownership</div>
                    <table style="width:100%; font-size:0.88rem;">
                        <tr><td style="color:#64748b; padding:6px 0;">Requested By:</td><td><strong>{record.submitted_by}</strong></td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Submitter Role:</td><td>{record.submitter_role}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Assignment Group:</td><td><strong>{record.assignment_group}</strong></td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Assigned Engineer:</td><td>{record.assigned_engineer or "Unassigned"}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Business Service:</td><td>{record.business_service}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Target Environment:</td><td>{record.target_environment}</td></tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Simulation Overview Banner
        if latest_assessment:
            st.markdown(
                f"""
                <div class="sg-card" style="border-left: 4px solid #0f62fe;">
                    <div class="sg-card-header">Simulation Risk Engine Assessment</div>
                    <div style="display: flex; gap: 2rem; align-items: center; margin-top: 8px;">
                        <div>Gate Verdict: {verdict_badge}</div>
                        <div>Composite Risk Score: {score_badge}</div>
                        <div>Identified Gaps: <strong>{latest_assessment.security_gaps_count}</strong></div>
                        <div>Blast Radius: <strong>{latest_assessment.blast_radius_nodes_count} nodes</strong></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.info(
                "💡 **No simulation assessment executed yet.** In Milestone D, submitting this change triggers deterministic pre-flight security simulation against the Apex Global Digital Twin."
            )

    # -------------------------------------------------------------------------
    # TAB 2: DESCRIPTION & JUSTIFICATION
    # -------------------------------------------------------------------------
    with tab_desc:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">Detailed Description</div>
                <div style="font-size:0.92rem; color:#1e293b; line-height:1.6; white-space:pre-wrap; background:#f8fafc; padding:1rem; border-radius:6px; border:1px solid #e2e8f0;">
{record.description}
                </div>
            </div>
            <div class="sg-card">
                <div class="sg-card-header">Business Justification</div>
                <div style="font-size:0.92rem; color:#1e293b; line-height:1.6; white-space:pre-wrap; background:#f8fafc; padding:1rem; border-radius:6px; border:1px solid #e2e8f0;">
{record.justification or "No justification provided."}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -------------------------------------------------------------------------
    # TAB 3: CONFIGURATION & DOMAIN
    # -------------------------------------------------------------------------
    with tab_ci:
        col_ci1, col_ci2 = st.columns(2)
        with col_ci1:
            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">Configuration Item Architecture</div>
                    <table style="width:100%; font-size:0.88rem;">
                        <tr><td style="color:#64748b; padding:6px 0;">Domain:</td><td><strong>{record.domain}</strong></td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Configuration Item:</td><td><strong>{record.configuration_item}</strong></td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Affected Application:</td><td>{record.affected_application}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Infrastructure Platform:</td><td>{record.infrastructure_platform}</td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Scenario Reference:</td><td><code>{record.scenario_name or "Custom Upload"}</code></td></tr>
                        <tr><td style="color:#64748b; padding:6px 0;">Source File:</td><td><code style="word-break:break-all;">{record.source_file_path or "None"}</code></td></tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_ci2:
            if record.firewall_details_json:
                try:
                    fw_dict = json.loads(record.firewall_details_json)
                    st.markdown(
                        f"""
                        <div class="sg-card">
                            <div class="sg-card-header">Firewall Policy Parameters</div>
                            <table style="width:100%; font-size:0.85rem;">
                                <tr><td style="color:#64748b; padding:4px 0;">Rule Name:</td><td><strong>{fw_dict.get('rule_name')}</strong></td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Device / Panorama:</td><td>{fw_dict.get('firewall_device')} ({fw_dict.get('panorama_reference')})</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Zones:</td><td>{fw_dict.get('source_zone')} → {fw_dict.get('destination_zone')}</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Addresses:</td><td><code>{fw_dict.get('source_addresses')}</code> → <code>{fw_dict.get('destination_addresses')}</code></td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">App-ID & Service:</td><td><code>{fw_dict.get('applications')}</code> / <code>{fw_dict.get('services')}</code></td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Protocol & Ports:</td><td>{fw_dict.get('protocol')} (Src: {fw_dict.get('source_port')}, Dst: {fw_dict.get('destination_port')})</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Action & Profile:</td><td><strong>{fw_dict.get('action')}</strong> ({fw_dict.get('security_profile')})</td></tr>
                            </table>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                except Exception:
                    st.write(record.firewall_details_json)

            elif record.sailpoint_details_json:
                try:
                    sp_dict = json.loads(record.sailpoint_details_json)
                    st.markdown(
                        f"""
                        <div class="sg-card">
                            <div class="sg-card-header">SailPoint Governance Parameters</div>
                            <table style="width:100%; font-size:0.85rem;">
                                <tr><td style="color:#64748b; padding:4px 0;">Target Identity:</td><td><strong>{sp_dict.get('identity_name')}</strong></td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Identity Profile & Source:</td><td>{sp_dict.get('identity_profile')} ({sp_dict.get('identity_source')})</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Account ID:</td><td><code>{sp_dict.get('account_id')}</code> ({sp_dict.get('account_status')})</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Requested Role:</td><td><strong>{sp_dict.get('requested_role')}</strong></td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Access Profile:</td><td>{sp_dict.get('access_profile')}</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Entitlement:</td><td><code>{sp_dict.get('entitlement')}</code></td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Target App & Expiry:</td><td>{sp_dict.get('application_name')} (Expiry: {sp_dict.get('access_expiry')})</td></tr>
                                <tr><td style="color:#64748b; padding:4px 0;">Governance States:</td><td>Req: {sp_dict.get('request_status')} | Appr: {sp_dict.get('approval_status')} | Prov: {sp_dict.get('provisioning_status')}</td></tr>
                            </table>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                except Exception:
                    st.write(record.sailpoint_details_json)

        # HCL Content Viewer
        if record.raw_content:
            st.markdown(
                """
                <div class="sg-card">
                    <div class="sg-card-header">Terraform HCL Payload</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.code(record.raw_content, language="hcl")

    # -------------------------------------------------------------------------
    # TAB 4: PLANNING
    # -------------------------------------------------------------------------
    with tab_plan:
        col_pl1, col_pl2 = st.columns(2)
        with col_pl1:
            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">Implementation Plan</div>
                    <div style="font-size:0.9rem; line-height:1.5;">{record.implementation_plan or "None specified"}</div>
                </div>
                <div class="sg-card">
                    <div class="sg-card-header">Technical Approach</div>
                    <div style="font-size:0.9rem; line-height:1.5;">{record.technical_approach or "None specified"}</div>
                </div>
                <div class="sg-card">
                    <div class="sg-card-header">Business Impact</div>
                    <div style="font-size:0.9rem; line-height:1.5;">{record.business_impact or "None specified"}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_pl2:
            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">Backout Plan</div>
                    <div style="font-size:0.9rem; line-height:1.5;">{record.backout_plan or "None specified"}</div>
                </div>
                <div class="sg-card">
                    <div class="sg-card-header">Validation Plan</div>
                    <div style="font-size:0.9rem; line-height:1.5;">{record.validation_plan or "None specified"}</div>
                </div>
                <div class="sg-card">
                    <div class="sg-card-header">Operational Impact</div>
                    <div style="font-size:0.9rem; line-height:1.5;">{record.operational_impact or "None specified"}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">Dependencies & Notes</div>
                <div style="font-size:0.9rem;"><strong>Dependencies:</strong> {record.dependencies or "None"}</div>
                <div style="font-size:0.9rem; margin-top:8px;"><strong>Additional Notes:</strong> {record.additional_notes or "None"}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -------------------------------------------------------------------------
    # TAB 5: SCHEDULE
    # -------------------------------------------------------------------------
    with tab_sched:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">Authorized Maintenance Window & Schedule</div>
                <table style="width:100%; font-size:0.9rem;">
                    <tr><td style="color:#64748b; padding:8px 0; width:220px;">Planned Start:</td><td><strong>{record.planned_start or "Unscheduled"}</strong></td></tr>
                    <tr><td style="color:#64748b; padding:8px 0;">Planned End:</td><td><strong>{record.planned_end or "Unscheduled"}</strong></td></tr>
                    <tr><td style="color:#64748b; padding:8px 0;">Maintenance Window:</td><td>{record.maintenance_window}</td></tr>
                    <tr><td style="color:#64748b; padding:8px 0;">Scheduling Notes:</td><td>{record.scheduling_notes or "None"}</td></tr>
                </table>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -------------------------------------------------------------------------
    # TAB 6: INITIAL RISK CONTEXT
    # -------------------------------------------------------------------------
    with tab_risk:
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">Requester Self-Assessed Risk Context</div>
                <table style="width:100%; font-size:0.9rem;">
                    <tr><td style="color:#64748b; padding:8px 0; width:260px;">Expected Business Impact:</td><td><strong>{record.expected_business_impact}</strong></td></tr>
                    <tr><td style="color:#64748b; padding:8px 0;">Expected Technical Impact:</td><td><strong>{record.expected_technical_impact}</strong></td></tr>
                    <tr><td style="color:#64748b; padding:8px 0;">Expected Service Disruption:</td><td><strong>{record.expected_service_disruption}</strong></td></tr>
                    <tr><td style="color:#64748b; padding:8px 0;">Requester Risk Notes:</td><td>{record.risk_context or "No additional notes provided."}</td></tr>
                </table>
                <div style="margin-top: 1rem; font-size: 0.82rem; color: #64748b; border-top: 1px solid #f1f5f9; padding-top: 0.75rem;">
                    * Requester risk declarations serve as administrative context for the Change Advisory Board (CAB) and do not substitute for SimuGuard AI deterministic simulation risk scoring.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -------------------------------------------------------------------------
    # TAB 7: ACTIVITY TIMELINE
    # -------------------------------------------------------------------------
    with tab_activity:
        st.markdown(
            """
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Audit Trail & Activity Log</span>
                    <span style="font-size:0.75rem; color:#64748b; font-weight:400;">Immutable lifecycle events</span>
                </div>
            """,
            unsafe_allow_html=True,
        )

        logs = repository.get_activity_logs(record.request_number)
        if logs:
            for log in reversed(logs):
                action_badge = render_workflow_badge(log.action)
                ts = log.timestamp[:19].replace("T", " ")
                st.markdown(
                    f"""
                    <div style="border-left: 2px solid #0f62fe; padding-left: 1rem; margin-bottom: 1rem; position: relative;">
                        <div style="display: flex; gap: 8px; align-items: center;">
                            {action_badge}
                            <span style="font-size: 0.88rem; font-weight: 600; color: #0f172a;">{log.action}</span>
                            <span style="color: #64748b; font-size: 0.8rem;">by <strong>{log.actor}</strong></span>
                            <span style="color: #94a3b8; font-size: 0.78rem;">at {ts} UTC</span>
                        </div>
                        <div style="font-size: 0.85rem; color: #475569; margin-top: 4px;">
                            {log.details or "No additional log details."}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.write("No activity logs recorded.")

        st.markdown("</div>", unsafe_allow_html=True)

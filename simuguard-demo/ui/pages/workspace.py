"""Single Assessment Workspace — Unified Engineer Experience.

Centers the entire pre-deployment change-risk workflow on one screen:
1. Paste ServiceNow Change Request.
2. Review Extracted Configuration (with inline warnings & ambiguity alerts).
3. Run Pre-Flight Assessment (deterministic simulation).
4. Inline Results: Verdict, Risk Score, Findings, Assets, Blast Radius,
   Remediation, Candidate HCL, Validation, Comparison, and PDF/JSON Downloads.
"""

from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import pandas as pd
import streamlit as st

from config.settings import CHANGES_DIR, PAGE_HISTORY, PAGE_SETTINGS
from storage.models import (
    AssessmentRecord,
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    FirewallChangeDetails,
    RemediationRecord,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_metric_card
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header
from ui.services.assessment_runner import AssessmentExecutionResult, AssessmentRunnerService
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)
from simuguard.models.enums import AssetCriticality, BlastTier
from ui.services.servicenow_extractor import (
    ChangeRequestSummary,
    ExtractedConfig,
    ServiceNowExtractor,
)


def _reset_assessment_and_form_state() -> None:
    """Clear previous assessment results and editable form widget caches for complete cross-request isolation."""
    st.session_state["current_assessment_result"] = None
    st.session_state["current_change_request"] = None
    widget_keys = [
        "cfg_domain", "cfg_firewall", "cfg_rule_name", "cfg_existing_rule",
        "cfg_src_zone", "cfg_src_cidr", "cfg_dst_zone", "cfg_dst_cidr",
        "cfg_action", "cfg_app", "cfg_service", "cfg_profile", "cfg_logging",
        "cfg_identity", "cfg_idp", "cfg_src", "cfg_acct", "cfg_role",
        "cfg_ap", "cfg_ent", "cfg_is_nat", "cfg_nat_orig_dst", "cfg_nat_trans_dst"
    ]
    for k in widget_keys:
        if k in st.session_state:
            del st.session_state[k]


def _load_sample_scenario(text: str) -> None:
    """Load a sample scenario text, reset stale state, and extract cleanly."""
    _reset_assessment_and_form_state()
    st.session_state["servicenow_raw_text"] = text
    st.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(text)
    st.rerun()


def render_single_workspace_page(repository: ChangeRepository) -> None:
    """Render the unified Single Assessment Workspace."""
    # -------------------------------------------------------------------------
    # 0. HEADER & ENVIRONMENT NOTICES
    # -------------------------------------------------------------------------
    current_env = st.session_state.get("environment_mode", "DEMO")
    show_tour = st.session_state.get("show_guided_tour", True)

    # Check if a historical record was requested to be loaded into workspace
    hist_req_no = st.session_state.get("workspace_request_number")
    if hist_req_no and "loaded_hist_request" not in st.session_state:
        _load_historical_record_into_workspace(repository, hist_req_no)
        st.session_state["loaded_hist_request"] = hist_req_no

    # Environment notice banner (satisfies guided tour & enterprise safety)
    if show_tour:
        if current_env == "DEMO":
            st.markdown(
                """
                <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 10px 14px; margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center;">
                    <div style="color: #166534; font-size: 0.88rem;">
                        <strong>🛡️ Demo Sandbox Active:</strong> Modelled on Apex Global Technologies synthetic digital twin (220 nodes, 77 edges). All operational statistics reflect verified demonstration scenarios.
                    </div>
                    <span class="sg-badge sg-badge-allow">DEMO SANDBOX</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div style="background-color: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 10px 14px; margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center;">
                    <div style="color: #1e40af; font-size: 0.88rem;">
                        <strong>🏢 Production Mode Active:</strong> Connected to isolated enterprise change history (<code>simuguard_history.db</code>). Real ITSM assessment audit logs are active.
                    </div>
                    <span class="sg-badge sg-badge-info">PRODUCTION</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # Workspace Title & Quick Tools
    col_hdr1, col_hdr2 = st.columns([3, 1])
    with col_hdr1:
        st.markdown(
            """
            <div style="margin-bottom: 0.75rem;">
                <h1 style="font-size: 1.6rem; font-weight: 700; color: #0f172a; margin: 0;">
                    🛡️ Change Risk Assessment Workspace
                </h1>
                <div style="font-size: 0.88rem; color: #64748b; margin-top: 4px;">
                    ServiceNow Pre-Flight Risk Engine • Single-Page Intake, Simulation, Remediation & Verification
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_hdr2:
        st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("🔄 Reset Form", use_container_width=True, key="btn_reset_workspace_form"):
                _clear_workspace_state()
                st.rerun()
        with col_btn2:
            if st.button("📋 History", use_container_width=True, key="btn_goto_history_from_ws"):
                st.session_state["active_page"] = PAGE_HISTORY
                st.rerun()

    # Initialize extraction state if absent
    if "extracted_config" not in st.session_state:
        # Default with sample PR-4082 for initial out-of-the-box convenience
        default_text = ServiceNowExtractor.get_sample_pr_4082()
        st.session_state["servicenow_raw_text"] = default_text
        st.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(default_text)

    # =========================================================================
    # SECTION 1: CHANGE REQUEST INPUT
    # =========================================================================
    st.markdown(
        """
        <div class="sg-card" style="margin-bottom: 1.25rem;">
            <div class="sg-card-header">
                <span>1. Paste Change Request</span>
                <span class="sg-badge sg-badge-info">ServiceNow Intake</span>
            </div>
            <div style="font-size: 0.85rem; color: #475569; margin: 0.5rem 0 0.75rem 0;">
                Paste your complete ServiceNow change ticket below. Supports Firewall policy specifications,
                Terraform HCL snippets, and SailPoint Identity Governance access requests.
            </div>
        """,
        unsafe_allow_html=True,
    )

    # Quick Template Buttons (One-click loaders)
    st.markdown(
        "<div style='font-size:0.75rem; font-weight:700; color:#1e293b; text-transform:uppercase; margin-bottom:6px;'>Sample Firewall Change Requests (Official Project Files):</div>",
        unsafe_allow_html=True,
    )
    col_c1, col_c2, col_c3, col_c4, col_c5 = st.columns(5)
    with col_c1:
        if st.button("📄 CHG-1001 (Outbound HTTPS)", key="load_chg1001", use_container_width=True):
            _load_sample_scenario(ServiceNowExtractor.get_sample_chg_1001())
    with col_c2:
        if st.button("📄 CHG-1002 (Unrestricted Egress)", key="load_chg1002", use_container_width=True):
            _load_sample_scenario(ServiceNowExtractor.get_sample_chg_1002())
    with col_c3:
        if st.button("📄 CHG-1003 (Internal DB Seg)", key="load_chg1003", use_container_width=True):
            _load_sample_scenario(ServiceNowExtractor.get_sample_chg_1003())
    with col_c4:
        if st.button("📄 CHG-1004 (Inbound NAT)", key="load_chg1004", use_container_width=True):
            _load_sample_scenario(ServiceNowExtractor.get_sample_chg_1004())
    with col_c5:
        if st.button("📄 CHG-1005 (Vendor Modify)", key="load_chg1005", use_container_width=True):
            _load_sample_scenario(ServiceNowExtractor.get_sample_chg_1005())

    with st.expander("⚡ Additional Scenarios (PR-4082, PR-4083, Netflix, Safe Rule, SailPoint)", expanded=False):
        col_t1, col_t2, col_t3, col_t4, col_t5 = st.columns(5)
        with col_t1:
            if st.button("📌 PR-4082 (DB Ingress)", key="load_pr4082", use_container_width=True):
                _load_sample_scenario(ServiceNowExtractor.get_sample_pr_4082())
        with col_t2:
            if st.button("📌 PR-4083 (DMZ & IAM)", key="load_pr4083", use_container_width=True):
                _load_sample_scenario(ServiceNowExtractor.get_sample_pr_4083())
        with col_t3:
            if st.button("📌 Netflix (Streaming)", key="load_netflix", use_container_width=True):
                _load_sample_scenario(ServiceNowExtractor.get_sample_allow_netflix())
        with col_t4:
            if st.button("📌 Safe Rule (Telemetry)", key="load_safe", use_container_width=True):
                _load_sample_scenario(ServiceNowExtractor.get_sample_safe_rule())
        with col_t5:
            if st.button("📌 SailPoint (S3 Access)", key="load_sp", use_container_width=True):
                _load_sample_scenario(ServiceNowExtractor.get_sample_sailpoint())

    # Large Text Area
    raw_input = st.text_area(
        label="ServiceNow Change Request Input",
        value=st.session_state.get("servicenow_raw_text", ""),
        height=300,
        placeholder="Paste your complete ServiceNow change request here...\n\nExample:\nChange Request: CHG004082\nShort Description: Allow direct database access for analytics\nSource Zone: Untrust-Internet\nDestination Zone: Prod-Database\nSource CIDR: 0.0.0.0/0\nDestination CIDR: 10.100.2.15/32\nApp-ID: any\nAction: allow",
        key="txt_servicenow_input",
    )
    st.session_state["servicenow_raw_text"] = raw_input

    # Single Prominent Extraction Action Button
    col_ext1, col_ext2 = st.columns([1, 4])
    with col_ext1:
        if st.button("🔍 Extract Configuration", use_container_width=True, key="btn_extract_config"):
            _reset_assessment_and_form_state()
            st.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(raw_input)
            st.toast("✅ Configuration extracted successfully!", icon="🔍")
            st.rerun()
    with col_ext2:
        cfg: ExtractedConfig = st.session_state.get("extracted_config", ExtractedConfig())
        domain_label = "Network Security (Firewall / IAM)" if cfg.domain == "NETWORK_SECURITY" else "Identity Governance (SailPoint ISC)"
        st.markdown(
            f"""
            <div style="padding-top: 8px; font-size: 0.85rem; color: #475569;">
                Detected Domain: <strong>{domain_label}</strong> • Rule/Target: <code>{cfg.rule_name or cfg.identity_name or 'Unspecified'}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # =========================================================================
    # SECTION 2: CHANGE REQUEST SUMMARY (PLAIN-ENGLISH)
    # =========================================================================
    _render_change_request_summary(cfg)

    # =========================================================================
    # SECTION 3: EXTRACTED CONFIGURATION REVIEW
    # =========================================================================
    st.markdown(
        """
        <div class="sg-card" style="margin-bottom: 1.25rem;">
            <div class="sg-card-header">
                <span>3. Extracted Configuration Review</span>
                <span class="sg-badge sg-badge-neutral">Editable Extracted Fields</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    # Missing & Ambiguous Fields Alerts
    if cfg.missing_fields:
        st.markdown(
            f"""
            <div style="background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 10px 14px; margin: 0.75rem 0; color: #991b1b; font-size: 0.85rem;">
                <strong>✕ Missing Mandatory Information:</strong> {", ".join(cfg.missing_fields)}. Please complete below.
            </div>
            """,
            unsafe_allow_html=True,
        )

    if cfg.warnings:
        warn_bullets = "".join([f"<li>{html.escape(w)}</li>" for w in cfg.warnings])
        st.markdown(
            f"""
            <div style="background-color: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 10px 14px; margin: 0.75rem 0; color: #92400e; font-size: 0.85rem;">
                <strong>⚠️ High-Risk / Ambiguous Configuration Parameters Detected:</strong>
                <ul style="margin: 4px 0 0 0; padding-left: 1.25rem;">{warn_bullets}</ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Editable Review Fields
    col_r1, col_r2, col_r3 = st.columns([2, 1, 1])
    with col_r1:
        cfg.title = st.text_input(
            "Short Description *",
            value=cfg.title or "Proposed Infrastructure Change",
            help="Summary description of the change.",
            key="cfg_title",
        )
    with col_r2:
        dom_options = ["Network Security / Firewall", "Identity Governance / SailPoint"]
        dom_idx = 0 if cfg.domain == "NETWORK_SECURITY" else 1
        sel_dom = st.selectbox("Change Domain *", options=dom_options, index=dom_idx, key="cfg_domain_sel")
        cfg.domain = "NETWORK_SECURITY" if "Network" in sel_dom else "IDENTITY_GOVERNANCE"
    with col_r3:
        prio_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        prio_idx = prio_options.index(cfg.priority) if cfg.priority in prio_options else 1
        cfg.priority = st.selectbox("Priority *", options=prio_options, index=prio_idx, key="cfg_priority_sel")

    if cfg.domain == "NETWORK_SECURITY":
        # Firewall & Network Specifications
        col_f1, col_f2, col_f3, col_f4 = st.columns(4)
        with col_f1:
            cfg.rule_name = st.text_input("Rule Name *", value=cfg.rule_name or "Allow-Egress-Rule", key="cfg_rule_name")
            cfg.source_zone = st.text_input("Source Zone *", value=cfg.source_zone or "Untrust-Internet", key="cfg_src_zone")
        with col_f2:
            cfg.destination_zone = st.text_input("Destination Zone *", value=cfg.destination_zone or "Prod-Database", key="cfg_dst_zone")
            cfg.source_addresses = st.text_input("Source CIDR *", value=cfg.source_addresses or "0.0.0.0/0", key="cfg_src_cidr")
        with col_f3:
            cfg.destination_addresses = st.text_input("Destination CIDR *", value=cfg.destination_addresses or "10.100.2.15/32", key="cfg_dst_cidr")
            cfg.applications = st.text_input("App-ID (Application) *", value=cfg.applications or "any", key="cfg_appid")
        with col_f4:
            cfg.services = st.text_input("Service / Port", value=cfg.services or "service-https", key="cfg_service")
            act_idx = 0 if cfg.action.lower() == "allow" else (1 if cfg.action.lower() == "deny" else 2)
            cfg.action = st.selectbox("Rule Action", options=["allow", "deny", "drop"], index=act_idx, key="cfg_action")

        # Inbound Destination NAT Sub-Card (Separates Public External IP from Private Translated Host)
        if getattr(cfg, "is_nat_change", False):
            st.markdown(
                """
                <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 10px 14px; margin: 0.75rem 0;">
                    <div style="font-weight: 700; color: #166534; font-size: 0.85rem; margin-bottom: 4px;">
                        🌐 Inbound Destination NAT Configuration (Public Endpoint vs Private Target Separation)
                    </div>
                    <div style="font-size: 0.8rem; color: #15803d;">
                        Destination NAT maps the external public endpoint to an internal private host. The security policy above authorizes traffic to the post-NAT private destination IP.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            col_nat1, col_nat2, col_nat3, col_nat4 = st.columns(4)
            with col_nat1:
                cfg.nat_rule_name = st.text_input("NAT Rule Name", value=cfg.nat_rule_name or "NAT-Inbound", key="cfg_nat_rule_name")
                cfg.nat_original_source_zone = st.text_input("Original Source Zone", value=cfg.nat_original_source_zone or "Untrust-Internet", key="cfg_nat_orig_sz")
            with col_nat2:
                cfg.nat_original_destination_zone = st.text_input("Original Dest Zone", value=cfg.nat_original_destination_zone or "Untrust-Internet", key="cfg_nat_orig_dz")
                cfg.nat_original_destination_address = st.text_input("Original Public IP *", value=cfg.nat_original_destination_address or "203.0.113.50/32", key="cfg_nat_orig_dst_ip", help="Pre-NAT external public IP")
            with col_nat3:
                cfg.nat_original_destination_port = st.text_input("Original Port", value=cfg.nat_original_destination_port or "443", key="cfg_nat_orig_port")
                cfg.nat_translated_destination_address = st.text_input("Translated Private IP *", value=cfg.nat_translated_destination_address or "10.100.30.25", key="cfg_nat_trans_dst_ip", help="Post-NAT internal destination host")
            with col_nat4:
                cfg.nat_translated_destination_port = st.text_input("Translated Port", value=cfg.nat_translated_destination_port or "443", key="cfg_nat_trans_port")

    else:
        # SailPoint Identity Governance Specifications
        l_type = getattr(cfg, "lifecycle_type", "ACCESS_REQUEST")
        if l_type == "MOVER":
            col_m1, col_m2, col_m3 = st.columns(3)
            with col_m1:
                cfg.identity_name = st.text_input("Target Identity *", value=cfg.identity_name or "", key="cfg_identity")
                cfg.current_department = st.text_input("Current Department", value=cfg.current_department or "", key="cfg_curr_dept")
                cfg.current_role = st.text_input("Current Role", value=cfg.current_role or "", key="cfg_curr_role")
            with col_m2:
                cfg.employee_id = st.text_input("Employee ID *", value=cfg.employee_id or "", key="cfg_emp_id")
                cfg.new_department = st.text_input("New Department *", value=cfg.new_department or "", key="cfg_new_dept")
                cfg.new_role = st.text_input("New Role *", value=cfg.new_role or cfg.requested_role or "", key="cfg_new_role")
                cfg.requested_role = cfg.new_role
            with col_m3:
                cfg.corporate_email = st.text_input("Corporate Email", value=cfg.corporate_email or "", key="cfg_email")
                cfg.effective_date = st.text_input("Effective Date", value=cfg.effective_date or "", key="cfg_eff_date")
                appr_opts = ["APPROVED", "PENDING", "REJECTED"]
                appr_idx = appr_opts.index(cfg.approval_status) if cfg.approval_status in appr_opts else 0
                cfg.approval_status = st.selectbox("Approval Status", options=appr_opts, index=appr_idx, key="cfg_appr_stat")

            col_acc1, col_acc2 = st.columns(2)
            with col_acc1:
                rem_val = ", ".join(cfg.access_to_remove) if cfg.access_to_remove else ""
                new_rem = st.text_area("Access to Remove / Revoke (comma-separated)", value=rem_val, height=75, key="cfg_acc_rem")
                cfg.access_to_remove = [x.strip() for x in new_rem.split(",") if x.strip()]
            with col_acc2:
                add_val = ", ".join(cfg.access_to_add) if cfg.access_to_add else ""
                new_add = st.text_area("Access to Add / Grant (comma-separated)", value=add_val, height=75, key="cfg_acc_add")
                cfg.access_to_add = [x.strip() for x in new_add.split(",") if x.strip()]

            items = []
            if cfg.access_to_add:
                items.append(f"ADD: {', '.join(cfg.access_to_add)}")
            if cfg.access_to_remove:
                items.append(f"REMOVE: {', '.join(cfg.access_to_remove)}")
            if items:
                cfg.entitlement = "; ".join(items)

        elif l_type == "JOINER":
            col_j1, col_j2, col_j3 = st.columns(3)
            with col_j1:
                cfg.identity_name = st.text_input("Employee Name *", value=cfg.identity_name or "", key="cfg_identity")
                cfg.new_department = st.text_input("Department *", value=cfg.new_department or cfg.department or "", key="cfg_dept")
            with col_j2:
                cfg.employee_id = st.text_input("Employee ID *", value=cfg.employee_id or "", key="cfg_emp_id")
                cfg.requested_role = st.text_input("Job Title / Role *", value=cfg.requested_role or cfg.new_role or "", key="cfg_role")
            with col_j3:
                cfg.start_date = st.text_input("Start Date", value=cfg.start_date or "", key="cfg_start_date")
                cfg.corporate_email = st.text_input("Corporate Email", value=cfg.corporate_email or "", key="cfg_email")

            add_val = ", ".join(cfg.access_to_add) if cfg.access_to_add else cfg.entitlement
            new_add = st.text_area("Requested Access / Entitlements *", value=add_val, height=75, key="cfg_acc_add")
            cfg.access_to_add = [x.strip() for x in new_add.split(",") if x.strip()]
            cfg.entitlement = new_add

        elif l_type == "LEAVER":
            col_l1, col_l2, col_l3 = st.columns(3)
            with col_l1:
                cfg.identity_name = st.text_input("Worker / Employee Name *", value=cfg.identity_name or "", key="cfg_identity")
                cfg.department = st.text_input("Department", value=cfg.department or cfg.current_department or "", key="cfg_dept")
            with col_l2:
                cfg.employee_id = st.text_input("Worker / Employee ID *", value=cfg.employee_id or cfg.worker_id or "", key="cfg_emp_id")
                cfg.termination_date = st.text_input("Termination Date", value=cfg.termination_date or "", key="cfg_term_date")
            with col_l3:
                cfg.worker_type = st.text_input("Worker Type", value=cfg.worker_type or "External contractor", key="cfg_wtype")
                appr_opts = ["APPROVED", "PENDING", "REJECTED"]
                appr_idx = appr_opts.index(cfg.approval_status) if cfg.approval_status in appr_opts else 0
                cfg.approval_status = st.selectbox("Approval Status", options=appr_opts, index=appr_idx, key="cfg_appr_stat")

            rem_val = ", ".join(cfg.access_to_remove) if cfg.access_to_remove else cfg.entitlement
            new_rem = st.text_area("Access to Revoke / Deprovision *", value=rem_val, height=75, key="cfg_acc_rem")
            cfg.access_to_remove = [x.strip() for x in new_rem.split(",") if x.strip()]
            cfg.entitlement = new_rem

        else:
            col_s1, col_s2, col_s3 = st.columns(3)
            with col_s1:
                cfg.identity_name = st.text_input("Target Identity *", value=cfg.identity_name or "", key="cfg_identity")
                cfg.requested_role = st.text_input("Requested Role *", value=cfg.requested_role or "", key="cfg_role")
            with col_s2:
                cfg.access_profile = st.text_input("Access Profile", value=cfg.access_profile or "", key="cfg_ap")
                cfg.entitlement = st.text_input("Entitlement *", value=cfg.entitlement or "", key="cfg_ent")
            with col_s3:
                cfg.identity_source = st.text_input("Authoritative Source", value=cfg.identity_source or "", key="cfg_src")
                cfg.account_id = st.text_input("Account ID", value=cfg.account_id or "", key="cfg_acct")

    # Expandable Advanced Details (Non-intrusive)
    with st.expander("⚙️ Advanced Change Metadata, Schedule & Justification", expanded=False):
        col_adv1, col_adv2 = st.columns(2)
        with col_adv1:
            cfg.requested_by = st.text_input("Requested By", value=cfg.requested_by or "SecOps Operations Engineer", key="cfg_requester")
            cfg.justification = st.text_area(
                "Business Justification",
                value=cfg.justification or "Operational configuration change required for business continuity.",
                height=70,
                key="cfg_justification",
            )
        with col_adv2:
            st.text_input("Configuration Item (CI)", value="PAN-NGFW-EDGE-01 (Active Internet Perimeter)", key="cfg_ci")
            st.text_input("Planned Schedule", value="Next Authorized Weekend Maintenance Window (Sat 02:00 - 06:00 UTC)", key="cfg_schedule")

    st.markdown("</div>", unsafe_allow_html=True)

    # =========================================================================
    # SECTION 4: RUN PRE-FLIGHT ASSESSMENT
    # =========================================================================
    st.markdown(
        """
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
            <div style="font-size: 0.95rem; font-weight: 600; color: #0f172a; margin-bottom: 0.5rem;">
                4. Run Pre-Flight Assessment
            </div>
            <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 1rem;">
                Simulates change against Digital Twin topology, evaluates security rules, predicts blast-radius impact,
                and executes closed-loop remediation validation.
            </div>
        """,
        unsafe_allow_html=True,
    )

    col_btn_run1, col_btn_run2, col_btn_run3 = st.columns([1, 2, 1])
    with col_btn_run2:
        run_assessment_clicked = st.button(
            "🚀 Run Pre-Flight Assessment",
            use_container_width=True,
            type="primary",
            key="btn_run_single_assessment",
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # Assessment Execution Handler
    if run_assessment_clicked:
        _execute_assessment_from_workspace(repository, cfg)
        st.rerun()

    # =========================================================================
    # SECTION 5: ASSESSMENT RESULTS
    # =========================================================================
    active_result: Optional[AssessmentExecutionResult] = st.session_state.get("current_assessment_result")
    active_req: Optional[ChangeRequestRecord] = st.session_state.get("current_change_request")

    if active_result and active_req:
        st.markdown(
            """
            <div style="border-top: 2px solid #0f62fe; padding-top: 1rem; margin-top: 1rem;">
                <h2 style="font-size: 1.4rem; font-weight: 700; color: #0f172a; margin: 0 0 1rem 0;">
                    5. Assessment Results & Remediation
                </h2>
            </div>
            """,
            unsafe_allow_html=True,
        )

        base_rep = active_result.baseline_report
        post_rep = active_result.post_report
        comp_rep = active_result.comparison_report
        verdict_val = base_rep.deployment_verdict.value
        risk_score_val = float(base_rep.overall_risk_score)

        # 4.1 Executive Verdict Banner
        _render_executive_verdict_banner(active_req, base_rep, post_rep)

        # 4.2 Top Metric KPI Cards Row
        col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
        with col_m1:
            render_metric_card(
                label="Baseline Risk Score",
                value=f"{int(round(risk_score_val))}/100",
                hint="Deterministic evaluation",
            )
        with col_m2:
            render_metric_card(
                label="Security Gaps",
                value=len(base_rep.identified_security_gaps),
                hint=f"{sum(1 for g in base_rep.identified_security_gaps if g.severity.value == 'CRITICAL')} Critical",
            )
        with col_m3:
            render_metric_card(
                label="Affected Assets",
                value=len(base_rep.predicted_affected_assets),
                hint="Blast radius scope",
            )
        with col_m4:
            post_score_str = f"{int(round(post_rep.overall_risk_score))}/100" if post_rep else "N/A"
            render_metric_card(
                label="Candidate Risk Score",
                value=post_score_str,
                hint="After remediation patch",
            )
        with col_m5:
            delta_val = comp_rep.risk_score_delta if comp_rep else (int(round(risk_score_val - post_rep.overall_risk_score)) if post_rep else 0)
            delta_str = f"-{delta_val} pts" if delta_val > 0 else f"{delta_val} pts"
            render_metric_card(
                label="Risk Reduction Delta",
                value=delta_str,
                hint="Closed-loop verification",
            )

        st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

        # 4.3 Structured Single-Workspace Tabs (All 10 user requirements inline!)
        tab_findings, tab_twin, tab_rem, tab_comp, tab_export = st.tabs(
            [
                f"🔍 Security Findings & Assets ({len(base_rep.identified_security_gaps)})",
                f"🌐 Digital Twin Blast Radius ({len(base_rep.predicted_affected_assets)})",
                "🛠️ Remediation & Candidate Patch",
                "⚖️ Before & After Comparison",
                "📄 Export Compliance Report",
            ]
        )

        with tab_findings:
            _render_findings_tab(base_rep)

        with tab_twin:
            _render_blast_radius_tab(base_rep)

        with tab_rem:
            _render_remediation_tab(active_result)

        with tab_comp:
            _render_comparison_tab(active_result)

        with tab_export:
            _render_export_tab(repository, active_req, active_result)


# =============================================================================
# WORKSPACE HELPER FUNCTIONS & SECTIONS
# =============================================================================

def _render_change_request_summary(cfg: ExtractedConfig) -> None:
    """Render plain-English business & SecOps summary of the extracted change request."""
    summary: ChangeRequestSummary = ServiceNowExtractor.generate_summary(cfg)

    st.markdown(
        """
        <div class="sg-card" style="margin-bottom: 1.25rem;">
            <div class="sg-card-header">
                <span>2. Change Request Summary</span>
                <span class="sg-badge sg-badge-info">Plain-English Review</span>
            </div>
            <div style="font-size: 0.85rem; color: #475569; margin: 0.5rem 0 0.75rem 0;">
                High-level business summary, technical modifications, and pre-assessment perimeter risk observations synthesized from the ingested change ticket.
            </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. What is being requested?
    st.markdown(
        f"""
        <div style="margin-bottom: 0.9rem;">
            <div style="font-weight: 700; color: #0f172a; font-size: 0.92rem; margin-bottom: 4px;">
                1. What is being requested?
            </div>
            <div style="font-size: 0.88rem; color: #334155; line-height: 1.5; background: #f8fafc; padding: 10px 14px; border-radius: 6px; border-left: 3px solid #0f62fe;">
                {html.escape(summary.what_is_requested)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Why is this change requested?
    st.markdown(
        f"""
        <div style="margin-bottom: 0.9rem;">
            <div style="font-weight: 700; color: #0f172a; font-size: 0.92rem; margin-bottom: 4px;">
                2. Why is this change requested?
            </div>
            <div style="font-size: 0.88rem; color: #334155; line-height: 1.5; background: #f8fafc; padding: 10px 14px; border-radius: 6px; border-left: 3px solid #10b981;">
                {html.escape(summary.why_requested)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Key configuration changes
    st.markdown(
        """
        <div style="margin-bottom: 0.6rem;">
            <div style="font-weight: 700; color: #0f172a; font-size: 0.92rem; margin-bottom: 6px;">
                3. Key configuration changes
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if summary.key_configuration_changes:
        display_params = list(summary.key_configuration_changes.items())
    elif cfg.domain == "NETWORK_SECURITY":
        display_params = [
            ("Target Firewall", cfg.target_firewall or "Not specified"),
            ("Security Policy", f"Modify '{cfg.existing_rule_name}' -> '{cfg.rule_name}'" if cfg.existing_rule_name else (cfg.rule_name or "Not specified")),
            ("Source Zone", cfg.source_zone or "Not specified"),
            ("Source CIDR", cfg.source_addresses or "Not specified"),
            ("Destination Zone", cfg.destination_zone or "Not specified"),
            ("Destination CIDR", cfg.destination_addresses or "Not specified"),
            ("Application", cfg.applications or "Not specified"),
            ("Service / Port", cfg.services or (f"TCP/{cfg.destination_port}" if cfg.destination_port else "Not specified")),
            ("Action", (cfg.action or "allow").upper()),
            ("Security Profile Group", cfg.security_profile or "Not specified"),
            ("Session Logging", cfg.logging or "Not specified"),
        ]
        if getattr(cfg, "is_nat_change", False):
            pub_t = f"{cfg.nat_original_destination_address}:{cfg.nat_original_destination_port}" if cfg.nat_original_destination_address else "Not specified"
            priv_t = f"{cfg.nat_translated_destination_address}:{cfg.nat_translated_destination_port}" if cfg.nat_translated_destination_address else "Not specified"
            display_params.append(("Destination NAT", f"{pub_t} -> {priv_t} ({cfg.nat_rule_name or 'NAT-Rule'})"))
    else:
        display_params = [
            ("Target Identity", cfg.identity_name or "Not specified"),
            ("Identity Profile", cfg.identity_profile or "Not specified"),
            ("Authoritative Source", cfg.identity_source or "Not specified"),
            ("Account ID", cfg.account_id or "Not specified"),
            ("Requested Role", cfg.requested_role or "Not specified"),
            ("Access Profile", cfg.access_profile or "Not specified"),
            ("Entitlement", cfg.entitlement or "Not specified"),
        ]

    df_config = pd.DataFrame(
        [{"Parameter": p[0], "Extracted Value": p[1]} for p in display_params]
    )
    st.dataframe(
        df_config,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Parameter": st.column_config.TextColumn("Parameter", width="medium"),
            "Extracted Value": st.column_config.TextColumn("Extracted Value", width="large"),
        },
    )

    # 4. Initial observations
    st.markdown(
        """
        <div style="margin-bottom: 0.6rem;">
            <div style="font-weight: 700; color: #0f172a; font-size: 0.92rem; margin-bottom: 6px;">
                4. Initial observations
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    obs_cards = []
    for obs in summary.initial_observations:
        is_warn = obs.startswith("⚠️")
        bg_col = "#fffbeb" if is_warn else "#f0fdf4"
        bd_col = "#fde68a" if is_warn else "#bbf7d0"
        txt_col = "#92400e" if is_warn else "#166534"
        obs_cards.append(
            f"""
            <div style="background-color: {bg_col}; border: 1px solid {bd_col}; border-radius: 6px; padding: 8px 12px; margin-bottom: 6px; color: {txt_col}; font-size: 0.84rem;">
                {html.escape(obs)}
            </div>
            """
        )
    st.markdown("".join(obs_cards), unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _render_executive_verdict_banner(
    record: ChangeRequestRecord,
    base_rep: Any,
    post_rep: Optional[Any],
) -> None:
    """Render prominent enterprise verdict card."""
    verdict = base_rep.deployment_verdict.value
    score = int(round(base_rep.overall_risk_score))

    if verdict == "BLOCK_DEPLOYMENT":
        border_color = "#ef4444"
        bg_color = "#fef2f2"
        badge = '<span class="sg-badge sg-badge-block">✕ VERDICT: BLOCK DEPLOYMENT</span>'
        summary = f"CRITICAL SECURITY VIOLATIONS DETECTED (Risk Score: {score}/100). Deployment must be halted pending remediation."
    elif verdict == "WARN_MANUAL_REVIEW":
        border_color = "#f59e0b"
        bg_color = "#fffbeb"
        badge = '<span class="sg-badge sg-badge-warn">▲ VERDICT: WARN (MANUAL REVIEW REQUIRED)</span>'
        summary = f"POLICY WARNINGS DETECTED (Risk Score: {score}/100). Manual review and CAB sign-off required before execution."
    else:
        border_color = "#10b981"
        bg_color = "#f0fdf4"
        badge = '<span class="sg-badge sg-badge-allow">● VERDICT: ALLOW (APPROVED FOR DEPLOYMENT)</span>'
        summary = f"CHANGE COMPLIANT (Risk Score: {score}/100). Configuration satisfies all zero-trust network and governance policies."

    st.markdown(
        f"""
        <div style="background-color: {bg_color}; border: 1px solid {border_color}; border-left: 6px solid {border_color}; border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div style="font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #475569;">
                    Pre-Flight Simulation Decision Gate • {record.request_number}
                </div>
                <div>{badge}</div>
            </div>
            <div style="font-size: 1.05rem; font-weight: 600; color: #0f172a; line-height: 1.4;">
                {summary}
            </div>
            <div style="font-size: 0.85rem; color: #475569; margin-top: 6px;">
                {html.escape(base_rep.executive_summary or '')}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_findings_tab(base_rep: Any) -> None:
    """Render Security Findings and Impacted Assets list."""
    st.markdown("#### 🛡️ Identified Security Gaps & Policy Violations")

    gaps = base_rep.identified_security_gaps
    if not gaps:
        st.success("✅ Zero security gaps identified! The configuration complies with all baseline security policies.")
    else:
        for idx, gap in enumerate(gaps, 1):
            sev = gap.severity.value
            badge = render_priority_badge(sev)
            st.markdown(
                f"""
                <div class="sg-card" style="margin-bottom: 0.75rem; border-left: 4px solid {'#ef4444' if sev == 'CRITICAL' else ('#f59e0b' if sev == 'HIGH' else '#3b82f6')};">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
                        <div style="font-size: 0.95rem; font-weight: 600; color: #0f172a;">
                            #{idx} • <code>{html.escape(gap.rule_id)}</code> — {html.escape(gap.gap_title)}
                        </div>
                        <div>{badge}</div>
                    </div>
                    <div style="font-size: 0.84rem; color: #334155; margin: 4px 0;">
                        <strong>Technical Impact:</strong> {html.escape(gap.technical_impact)}
                    </div>
                    <div style="font-size: 0.82rem; color: #0f62fe; margin-top: 4px;">
                        <strong>Compliance Violation:</strong> {html.escape(gap.compliance_violation or 'Enterprise Baseline')}
                    </div>
                    <div style="background-color: #f8fafc; border-radius: 4px; padding: 6px 10px; margin-top: 6px; font-size: 0.82rem; color: #475569;">
                        💡 <strong>Remediation Guidance:</strong> {html.escape(gap.remediation_guidance)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)
    st.markdown("#### 🏢 Directly Affected Infrastructure Assets")
    assets = base_rep.predicted_affected_assets
    if not assets:
        st.info("No directly affected infrastructure assets were identified from the available Digital Twin data.")
    else:
        rows = []
        for a in assets:
            try:
                asset_name = getattr(a, "asset_name", None) or getattr(a, "asset_id", "Unknown Asset")
                asset_id = getattr(a, "asset_id", "N/A")
                asset_type = getattr(a, "asset_type", None) or "Infrastructure Node"

                crit = getattr(a, "criticality", AssetCriticality.HIGH)
                crit_val = crit.value if hasattr(crit, "value") else str(crit)

                tier = getattr(a, "blast_tier", BlastTier.DIRECT)
                tier_val = tier.value if hasattr(tier, "value") else str(tier)
                impact_nature = "Direct Impact" if "DIRECT" in tier_val.upper() else "Indirect Impact"
                badge_type = "block" if "DIRECT" in tier_val.upper() else "warn"
                tier_badge = f'<span class="sg-badge sg-badge-{badge_type}">{html.escape(tier_val)} ({impact_nature})</span>'

                data_class = getattr(a, "data_classification", None)
                if data_class:
                    data_class_display = f'<span style="color: #0f62fe; font-weight: 600;">{html.escape(str(data_class))}</span>'
                else:
                    data_class_display = '<span style="color: #94a3b8; font-style: italic;">Not available</span>'

                rel_desc = (
                    getattr(a, "impact_description", None)
                    or getattr(a, "impact_rationale", None)
                    or "Impacted by network/identity policy change"
                )

                rows.append(
                    f"""
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 8px;">
                            <div style="font-weight: 600; color: #1e293b;">{html.escape(str(asset_name))}</div>
                            <div style="font-size: 0.75rem; color: #64748b; font-family: monospace;">ID: {html.escape(str(asset_id))}</div>
                        </td>
                        <td style="padding: 10px 8px; font-size: 0.84rem; color: #475569;">{html.escape(str(asset_type))}</td>
                        <td style="padding: 10px 8px; font-size: 0.84rem; font-weight: 600; color: #0f172a;">{html.escape(crit_val)}</td>
                        <td style="padding: 10px 8px;">{tier_badge}</td>
                        <td style="padding: 10px 8px; font-size: 0.84rem;">{data_class_display}</td>
                        <td style="padding: 10px 8px; font-size: 0.82rem; color: #334155;">{html.escape(str(rel_desc))}</td>
                    </tr>
                    """
                )
            except Exception:
                asset_id_fallback = getattr(a, "asset_id", "Unknown")
                rows.append(
                    f"""
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 8px; font-weight: 600; color: #1e293b;">{html.escape(str(asset_id_fallback))}</td>
                        <td style="padding: 10px 8px; font-size: 0.84rem; color: #475569;">Unknown Type</td>
                        <td style="padding: 10px 8px; font-size: 0.84rem;">MEDIUM</td>
                        <td style="padding: 10px 8px;"><span class="sg-badge sg-badge-warn">INDIRECT</span></td>
                        <td style="padding: 10px 8px; font-size: 0.84rem; color: #94a3b8;">Not available</td>
                        <td style="padding: 10px 8px; font-size: 0.82rem; color: #64748b;">Impacted asset</td>
                    </tr>
                    """
                )

        st.markdown(
            f"""
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left;">
                    <thead>
                        <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0; color: #475569; font-size: 0.75rem; text-transform: uppercase;">
                            <th style="padding: 8px;">Asset Name & ID</th>
                            <th style="padding: 8px;">Asset Type</th>
                            <th style="padding: 8px;">Criticality</th>
                            <th style="padding: 8px;">Impact Nature</th>
                            <th style="padding: 8px;">Data Classification</th>
                            <th style="padding: 8px;">Relationship / Impact</th>
                        </tr>
                    </thead>
                    <tbody>{"".join(rows)}</tbody>
                </table>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_blast_radius_tab(base_rep: Any) -> None:
    """Render Digital Twin Blast Radius analysis and traversed nodes."""
    st.markdown("#### 🌐 Digital Twin Topology & Blast Radius Analysis")

    assets = base_rep.predicted_affected_assets
    total_assets = len(assets)
    direct_assets = sum(1 for a in assets if "DIRECT" in (getattr(a.blast_tier, "value", str(a.blast_tier))))
    indirect_assets = total_assets - direct_assets

    col_t1, col_t2, col_t3 = st.columns(3)
    with col_t1:
        render_metric_card("Total Nodes in Blast Scope", total_assets, "Digital Twin graph traversal")
    with col_t2:
        render_metric_card("Direct Exposure Assets", direct_assets, "Unshielded entrypoints")
    with col_t3:
        render_metric_card("Transitive Dependency Reach", indirect_assets, "Downstream databases & services")

    st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class="sg-card" style="margin-bottom: 1rem;">
            <div class="sg-card-header">
                <span>Enterprise Blast Radius Scope</span>
                <span class="sg-badge sg-badge-info">Apex Global Digital Twin</span>
            </div>
            <div style="padding: 0.5rem 0; font-size: 0.85rem; color: #334155; line-height: 1.6;">
                The Blast Radius Analyzer traces inbound paths from unverified network ingress and overly-permissive
                IAM trust policies through PAN-OS edge firewalls into core workload subnets.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Detailed table of affected nodes
    if assets:
        for a in assets:
            try:
                asset_name = getattr(a, "asset_name", None) or getattr(a, "asset_id", "Unknown Asset")
                asset_type = getattr(a, "asset_type", "Infrastructure Node")
                asset_id = getattr(a, "asset_id", "N/A")
                blast_tier = getattr(a, "blast_tier", BlastTier.DIRECT)
                tier_val = blast_tier.value if hasattr(blast_tier, "value") else str(blast_tier)
                impact_nature = "Direct Impact" if "DIRECT" in tier_val.upper() else "Indirect Impact"
                crit = getattr(a, "criticality", AssetCriticality.HIGH)
                crit_val = crit.value if hasattr(crit, "value") else str(crit)
                data_class = getattr(a, "data_classification", None) or "Not available"
                impact_desc = (
                    getattr(a, "impact_description", None)
                    or getattr(a, "impact_rationale", None)
                    or "Downstream dependency reach"
                )
                violations = getattr(a, "compliance_violations", None) or []

                with st.expander(f"📍 {asset_name} ({asset_type}) — Classification: {data_class}"):
                    st.write(f"**Asset ID:** `{asset_id}`")
                    st.write(f"**Criticality:** `{crit_val}`")
                    st.write(f"**Blast Tier:** `{tier_val}` ({impact_nature})")
                    st.write(f"**Relationship to Proposed Change:** {impact_desc}")
                    if violations:
                        st.write(f"**Direct Violations:** {', '.join(violations)}")
            except Exception:
                continue
    else:
        st.info("No directly affected infrastructure assets were identified from the available Digital Twin data.")


def _render_remediation_tab(result: AssessmentExecutionResult) -> None:
    """Render synthesized candidate configuration, patch, and validation checks."""
    st.markdown("#### 🛠️ Automated Remediation & Candidate Policy Patch")

    plan = result.remediation_plan
    post_rep = result.post_report

    if not plan:
        st.info("No automated remediation plan required for this compliant change.")
        return

    # Recommendations List
    st.markdown("##### 📋 Actionable Remediation Recommendations")
    for r in plan.recommendations:
        title_text = getattr(r, "explanation", "") or getattr(r, "action_summary", "") or f"Remediation for {r.rule_id}"
        target_res = getattr(r, "affected_resource", "") or getattr(r, "target_resource", "Security Rule")
        benefit_text = getattr(r, "security_benefit", "") or getattr(r, "justification", "Least-privilege scoping")
        conf_pct = int(getattr(r, "confidence_score", 0.95) * 100)
        st.markdown(
            f"""
            <div class="sg-card" style="margin-bottom: 0.5rem; border-left: 3px solid #10b981;">
                <div style="font-weight: 600; color: #0f172a; font-size: 0.9rem;">
                    💡 [{r.rule_id}] {html.escape(title_text)}
                </div>
                <div style="font-size: 0.82rem; color: #475569; margin-top: 2px;">
                    Target Resource: <code>{html.escape(target_res)}</code> • Confidence: <code>{conf_pct}%</code>
                </div>
                <div style="font-size: 0.8rem; color: #059669; margin-top: 4px;">
                    Security Benefit: {html.escape(benefit_text)}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Synthesized Candidate Configuration Code
    st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)
    st.markdown("##### 📄 Synthesized Candidate Configuration (Diff / Patch)")
    st.caption("Generated by SimuGuard ConfigGenerator using least-privilege scoping rules.")
    candidate_code = plan.synthesized_candidate_hcl or "# Candidate configuration synthesized."
    st.code(candidate_code, language="hcl")

    # Closed-loop Candidate Validation Results
    if post_rep:
        st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)
        st.markdown("##### ✅ Closed-Loop Candidate Validation Checks")
        post_verdict = post_rep.deployment_verdict.value
        post_badge = render_verdict_badge(post_verdict)
        st.markdown(
            f"""
            <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 10px 14px; margin-bottom: 0.75rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="font-size: 0.88rem; color: #166534;">
                    Candidate Validation Verdict: <strong>{post_verdict}</strong> (Post-Remediation Score: <strong>{int(round(post_rep.overall_risk_score))}/100</strong>)
                </div>
                <div>{post_badge}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        checks = post_rep.pre_implementation_validation_plan or []
        if checks:
            for c in checks:
                step_no = getattr(c, "step_number", 1) if not isinstance(c, dict) else c.get("step_number", 1)
                target = getattr(c, "target_component", "") if not isinstance(c, dict) else c.get("target_component", "")
                what = getattr(c, "what_to_validate", "") if not isinstance(c, dict) else c.get("what_to_validate", "")
                cmd = getattr(c, "cli_command", "") if not isinstance(c, dict) else c.get("cli_command", "")
                crit = getattr(c, "expected_pass_criteria", "") if not isinstance(c, dict) else c.get("expected_pass_criteria", "")
                desc = what or target or f"Step {step_no}"
                st.markdown(
                    f"- ✅ **Step {step_no}: {target}** — {desc} (Run: `{cmd}`, Expected: `{crit}`)"
                )


def _render_comparison_tab(result: AssessmentExecutionResult) -> None:
    """Render Before-and-After differential comparison metrics and resolution tracking."""
    st.markdown("#### ⚖️ Before & After Validation Comparison")

    comp = result.comparison_report
    base_rep = result.baseline_report
    post_rep = result.post_report

    if not post_rep:
        st.info("Before & After comparison requires candidate overlay evaluation.")
        return

    score_before = int(round(base_rep.overall_risk_score))
    score_after = int(round(post_rep.overall_risk_score))
    delta = score_before - score_after

    col_c1, col_c2, col_c3 = st.columns(3)
    with col_c1:
        render_metric_card(
            label="Baseline Risk",
            value=f"{score_before}/100",
            hint=f"Verdict: {base_rep.deployment_verdict.value}",
        )
    with col_c2:
        render_metric_card(
            label="Remediated Risk",
            value=f"{score_after}/100",
            hint=f"Verdict: {post_rep.deployment_verdict.value}",
        )
    with col_c3:
        render_metric_card(
            label="Net Risk Reduction",
            value=f"-{delta} pts",
            hint="Deterministic drop",
        )

    st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

    # Resolution Breakdown
    resolved_count = comp.resolved_count if comp else max(0, len(base_rep.identified_security_gaps) - len(post_rep.identified_security_gaps))
    unresolved_count = len(post_rep.identified_security_gaps)

    st.markdown(
        f"""
        <div class="sg-card">
            <div class="sg-card-header">
                <span>Security Gap Resolution Tracking</span>
                <span class="sg-badge sg-badge-allow">{resolved_count} Resolved</span>
            </div>
            <div style="font-size: 0.88rem; color: #334155; line-height: 1.6; padding: 0.5rem 0;">
                <ul style="margin: 0; padding-left: 1.25rem;">
                    <li><strong>Resolved Policy Violations:</strong> {resolved_count} security gaps successfully mitigated by candidate patch.</li>
                    <li><strong>Unresolved / Residual Risks:</strong> {unresolved_count} items remaining for operational verification.</li>
                    <li><strong>Blast Radius Contraction:</strong> Asset exposure reduced from {len(base_rep.predicted_affected_assets)} down to {len(post_rep.predicted_affected_assets)} nodes.</li>
                </ul>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_export_tab(
    repository: ChangeRepository,
    record: ChangeRequestRecord,
    result: AssessmentExecutionResult,
) -> None:
    """Render publication-grade PDF and JSON download buttons."""
    st.markdown("#### 📄 Export Compliance & Audit Reports")
    st.write("Generate official Change Advisory Board (CAB) documentation and machine-readable audit artifacts.")

    # Fetch latest stored records
    base_asmt = repository.get_latest_assessment(record.request_number, assessment_type="ORIGINAL")
    rem_rec = repository.get_remediation_record(record.request_number)

    if not base_asmt:
        st.warning("Assessment record not yet committed to repository.")
        return

    # PDF & JSON Generation
    pdf_bytes = build_executive_pdf(record, base_asmt, rem_rec)
    pdf_filename = get_safe_export_filename(record.request_number, base_asmt.assessment_id, "pdf")

    json_str = build_executive_json(record, base_asmt, rem_rec)
    json_filename = get_safe_export_filename(record.request_number, base_asmt.assessment_id, "json")

    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        st.markdown(
            """
            <div class="sg-card" style="text-align: center; padding: 1.5rem 1rem;">
                <div style="font-size: 2rem;">📑</div>
                <div style="font-weight: 700; color: #0f172a; margin: 4px 0;">Executive PDF Report</div>
                <div style="font-size: 0.8rem; color: #64748b; margin-bottom: 1rem;">
                    Formal multi-page audit report with running headers, findings matrix, and CAB sign-off section.
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            label="📥 Download Executive PDF Report",
            data=pdf_bytes,
            file_name=pdf_filename,
            mime="application/pdf",
            use_container_width=True,
            key="btn_ws_download_pdf",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col_exp2:
        st.markdown(
            """
            <div class="sg-card" style="text-align: center; padding: 1.5rem 1rem;">
                <div style="font-size: 2rem;">💾</div>
                <div style="font-weight: 700; color: #0f172a; margin: 4px 0;">Compliance Audit JSON</div>
                <div style="font-size: 0.8rem; color: #64748b; margin-bottom: 1rem;">
                    Complete schema-validated audit artifact for automated CI/CD and SIEM telemetry pipelines.
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            label="📥 Download Audit JSON Export",
            data=json_str,
            file_name=json_filename,
            mime="application/json",
            use_container_width=True,
            key="btn_ws_download_json",
        )
        st.markdown("</div>", unsafe_allow_html=True)


# =============================================================================
# WORKFLOW EXECUTION & RECORD PERSISTENCE
# =============================================================================

def _execute_assessment_from_workspace(repository: ChangeRepository, cfg: ExtractedConfig) -> None:
    """Execute pre-flight simulation and update session state."""
    # 1. Generate or reuse request number
    req_no = cfg.request_number
    if not req_no or not req_no.strip():
        req_no = repository.generate_next_request_number()
        cfg.request_number = req_no

    # 2. Construct Domain Details
    fw_details = FirewallChangeDetails(
        firewall_platform=cfg.firewall_platform,
        firewall_device=cfg.firewall_device,
        rule_name=cfg.rule_name,
        source_zone=cfg.source_zone,
        destination_zone=cfg.destination_zone,
        source_addresses=cfg.source_addresses,
        destination_addresses=cfg.destination_addresses,
        applications=cfg.applications,
        services=cfg.services,
        destination_port=cfg.destination_port,
        action=cfg.action,
        security_profile=cfg.security_profile,
    ) if cfg.domain == "NETWORK_SECURITY" else None

    sp_details = SailPointChangeDetails(
        identity_name=cfg.identity_name,
        employee_id=cfg.employee_id,
        worker_id=cfg.worker_id,
        worker_type=cfg.worker_type,
        corporate_email=cfg.corporate_email,
        identity_profile=cfg.identity_profile,
        identity_source=cfg.identity_source or "SailPoint ISC",
        account_id=cfg.account_id,
        account_status=cfg.account_status,
        manager=cfg.manager,
        manager_id=cfg.manager_id,
        department=cfg.department or cfg.new_department or cfg.current_department,
        current_department=cfg.current_department,
        new_department=cfg.new_department,
        current_role=cfg.current_role,
        new_role=cfg.new_role,
        location=cfg.location,
        requested_role=cfg.requested_role or cfg.new_role,
        access_profile=cfg.access_profile,
        entitlement=cfg.entitlement,
        access_to_add=cfg.access_to_add,
        access_to_remove=cfg.access_to_remove,
        privileged_access_requested=cfg.privileged_access_requested,
        privileged_entitlements=cfg.privileged_entitlements,
        business_justification=cfg.justification,
        approval_status=cfg.approval_status or "PENDING",
        start_date=cfg.start_date,
        effective_date=cfg.effective_date,
        termination_date=cfg.termination_date,
        lifecycle_type=cfg.lifecycle_type,
        role_name=getattr(cfg, "role_name", ""),
        role_arn=getattr(cfg, "role_arn", ""),
        target_role_name=getattr(cfg, "target_role_name", ""),
        target_role_arn=getattr(cfg, "target_role_arn", ""),
        source_role_name=getattr(cfg, "source_role_name", ""),
        source_role_arn=getattr(cfg, "source_role_arn", ""),
        source_identity_record_id=getattr(cfg, "source_identity_record_id", ""),
        requested_policy_name=getattr(cfg, "requested_policy_name", ""),
        identity_record_id=getattr(cfg, "identity_record_id", ""),
        aws_account=getattr(cfg, "aws_account", ""),
        source_aws_account=getattr(cfg, "source_aws_account", ""),
        target_aws_account=getattr(cfg, "target_aws_account", ""),
        assigned_workload=getattr(cfg, "assigned_workload", ""),
        current_attached_policies=getattr(cfg, "current_attached_policies", []),
        permission_boundary=getattr(cfg, "permission_boundary", ""),
        permission_boundary_arn=getattr(cfg, "permission_boundary_arn", ""),
        boundary_action=getattr(cfg, "boundary_action", ""),
        trust_relationship_id=getattr(cfg, "trust_relationship_id", ""),
        trusted_principal=getattr(cfg, "trusted_principal", ""),
        mfa_condition=getattr(cfg, "mfa_condition", ""),
        external_id_condition=getattr(cfg, "external_id_condition", ""),
    ) if cfg.domain == "IDENTITY_GOVERNANCE" else None

    # 3. Construct and save ChangeRequestRecord in SQLite
    existing_rec = repository.get_change_request(req_no)
    if existing_rec:
        record = existing_rec
        record.title = cfg.title or record.title
        record.justification = cfg.justification or record.justification
        record.priority = cfg.priority or record.priority
        record.raw_content = cfg.raw_hcl or record.raw_content
        if cfg.scenario_source_path:
            record.source_file_path = cfg.scenario_source_path
        if fw_details:
            record.firewall_details_json = fw_details.model_dump_json()
        if sp_details:
            record.sailpoint_details_json = sp_details.model_dump_json()
        repository.update_change_request(record)
    else:
        record = ChangeRequestRecord(
            request_number=req_no,
            title=cfg.title or f"Change Request {req_no}",
            description=cfg.title or "Submitted via ServiceNow Assessment Workspace",
            justification=cfg.justification or "Standard operational change.",
            submitted_by=cfg.requested_by or "SecOps Operations Engineer",
            submitter_role="Network Security Operations",
            change_type=cfg.change_type or "NORMAL",
            domain=ChangeDomain.NETWORK_SECURITY.value if cfg.domain == "NETWORK_SECURITY" else ChangeDomain.IDENTITY_GOVERNANCE.value,
            priority=cfg.priority or "HIGH",
            status=WorkflowState.SUBMITTED.value,
            category="Network Security" if cfg.domain == "NETWORK_SECURITY" else "Identity Governance",
            subcategory="Firewall Rule" if cfg.domain == "NETWORK_SECURITY" else "Access Request",
            source_file_path=cfg.scenario_source_path,
            raw_content=cfg.raw_hcl,
            firewall_details_json=fw_details.model_dump_json() if fw_details else None,
            sailpoint_details_json=sp_details.model_dump_json() if sp_details else None,
        )
        repository.create_change_request(record)

    # 4. Execute AssessmentRunnerService
    runner = AssessmentRunnerService(repository=repository)
    with st.spinner("Executing pre-flight simulation and remediation engine..."):
        ok, msg, result = runner.run_assessment(req_no, force_reassessment=True)

    if ok and result:
        st.session_state["current_assessment_result"] = result
        st.session_state["current_change_request"] = repository.get_change_request(req_no)
        st.toast(f"✅ Assessment complete for {req_no}!", icon="🛡️")
    else:
        st.error(f"Assessment error: {msg}")


def _load_historical_record_into_workspace(repository: ChangeRepository, req_no: str) -> None:
    """Load an existing database record and its assessment results into the workspace."""
    record = repository.get_change_request(req_no)
    if not record:
        return

    # Extract text and configuration
    text_content = record.raw_content or f"Change Request: {record.request_number}\nTitle: {record.title}\nDomain: {record.domain}"
    st.session_state["servicenow_raw_text"] = text_content
    cfg = ServiceNowExtractor.extract_from_text(text_content)
    cfg.request_number = record.request_number
    cfg.title = record.title
    cfg.priority = record.priority
    st.session_state["extracted_config"] = cfg

    # Load stored assessment execution result
    runner = AssessmentRunnerService(repository=repository)
    ok, msg, res = runner.run_assessment(req_no, force_reassessment=False)
    if not ok:
        # If already assessed, run with force to load in-memory execution container
        ok, msg, res = runner.run_assessment(req_no, force_reassessment=True)

    if ok and res:
        st.session_state["current_assessment_result"] = res
        st.session_state["current_change_request"] = record


def _clear_workspace_state() -> None:
    """Clear active form and results state for a fresh assessment."""
    for key in [
        "servicenow_raw_text",
        "extracted_config",
        "current_assessment_result",
        "current_change_request",
        "workspace_request_number",
        "loaded_hist_request",
    ]:
        if key in st.session_state:
            del st.session_state[key]

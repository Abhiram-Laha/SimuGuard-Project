"""New Change Request intake form — ServiceNow-inspired enterprise interface."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import streamlit as st

from config.settings import PAGE_HISTORY, PAGE_OVERVIEW
from storage.models import (
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    FirewallChangeDetails,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from storage.upload_handler import validate_and_stage_upload
from ui.components.status_badges import render_priority_badge, render_workflow_badge
from ui.layout import render_page_header
from ui.services.dataset_service import get_dataset_service


def render_new_change_page(repository: ChangeRepository) -> None:
    """Render the enterprise ServiceNow-inspired Change Request form."""
    dataset_service = get_dataset_service()

    # Pre-generate next sequential request number
    if "form_request_number" not in st.session_state:
        st.session_state["form_request_number"] = repository.generate_next_request_number()

    request_number = st.session_state["form_request_number"]

    # Header
    st.markdown(
        f"""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; font-weight: 600;">ServiceNow Change Management • Pre-Flight Intake</span>
                    <h1 style="font-size: 1.5rem; font-weight: 700; color: #0f172a; margin: 4px 0 0 0;">
                        Change Request: <span style="color: #0f62fe; font-family: monospace;">{request_number}</span>
                    </h1>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <span class="sg-badge sg-badge-neutral">STATE: DRAFT / PENDING SUBMISSION</span>
                    <span class="sg-badge sg-badge-info">ENV: APEX GLOBAL PRODUCTION</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Scenarios available on disk
    scenarios = dataset_service.get_available_scenarios()

    # =========================================================================
    # FORM INTAKE
    # =========================================================================
    with st.form("new_change_request_form", clear_on_submit=False):
        # ---------------------------------------------------------------------
        # SECTION A: CHANGE INFORMATION
        # ---------------------------------------------------------------------
        st.markdown(
            """
            <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                    Section A — Change Information
                </h3>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_a1, col_a2 = st.columns(2)
        with col_a1:
            title = st.text_input(
                "Short Description *",
                value="",
                placeholder="e.g. Open Outbound Egress for Analytics Telemetry",
                help="Mandatory summary of the proposed change.",
            )
            change_type = st.selectbox(
                "Change Type *",
                options=["Normal", "Standard", "Emergency", "Expedited"],
                index=0,
            )
            priority = st.selectbox(
                "Priority *",
                options=["Critical", "High", "Medium", "Low"],
                index=1,
            )
            requested_by = st.text_input(
                "Requested By",
                value="David Kim (Senior Network Security Operations Engineer)",
            )
            assignment_group = st.selectbox(
                "Assignment Group",
                options=[
                    "SecOps-Network-Team",
                    "SecOps-Cloud-Team",
                    "Identity-Operations-Team",
                    "Enterprise-Architecture-CAB",
                ],
                index=0,
            )

        with col_a2:
            category = st.selectbox(
                "Category",
                options=["Network Security", "Identity Governance", "Cloud Infrastructure", "Applications"],
                index=0,
            )
            subcategory = st.selectbox(
                "Subcategory",
                options=["Firewall Rule", "IAM Policy Attachment", "SailPoint Role Assignment", "Routing / NAT"],
                index=0,
            )
            business_service = st.selectbox(
                "Business Service",
                options=[
                    "Enterprise Network Perimeter",
                    "Customer Digital Channels",
                    "Treasury & Financial Core",
                    "Data Lake Analytics Pipeline",
                    "Corporate Identity Federation",
                ],
                index=0,
            )
            assigned_to = st.text_input("Assigned To", value="SecOps Operations")
            submitter_role = st.text_input(
                "Submitter Role", value="Network Security Operations"
            )

        description = st.text_area(
            "Detailed Description *",
            value="",
            placeholder="Describe the operational and technical objective of this configuration change...",
            height=90,
            help="Mandatory full description of the change.",
        )

        justification = st.text_area(
            "Business Justification *",
            value="",
            placeholder="Provide business justification, business owner approval reference, or incident ticket...",
            height=80,
            help="Mandatory business reason for requesting the change.",
        )

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # SECTION B: CONFIGURATION ITEMS & SOURCE
        # ---------------------------------------------------------------------
        st.markdown(
            """
            <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                    Section B — Configuration Items & Architecture Scope
                </h3>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_b1, col_b2 = st.columns(2)
        with col_b1:
            domain_choice = st.selectbox(
                "Change Domain *",
                options=[
                    "Network Security / Firewall",
                    "Identity Governance / SailPoint",
                ],
                index=0,
                key="form_domain_choice",
            )
            apps = dataset_service.get_applications()
            app_options = [f"{a.get('name', 'App')} ({a.get('id', '')})" for a in apps] or ["Customer Web Portal"]
            affected_app = st.selectbox("Affected Business Application", options=app_options, index=0)
            target_env = st.selectbox(
                "Target Environment",
                options=[
                    "Apex Global Production (Digital Twin)",
                    "Apex Global Staging / Pre-Prod",
                    "Apex Development Sandboxes",
                ],
                index=0,
            )

        with col_b2:
            config_item = st.text_input(
                "Configuration Item (CI)",
                value="PAN-NGFW-EDGE-01 (Internet Perimeter Active)",
            )
            infra_platform = st.selectbox(
                "Infrastructure Platform",
                options=[
                    "Palo Alto Networks PAN-OS 11.1 (PA-5450)",
                    "AWS VPC Security Groups & IAM",
                    "SailPoint Identity Security Cloud",
                    "Hybrid Perimeter & Identity Infrastructure",
                ],
                index=0,
            )

        is_identity_gov = "Identity" in domain_choice

        # Scenario or Upload Source
        selected_scenario_key: Optional[str] = None
        if is_identity_gov:
            st.markdown("#### Configuration Payload Source")
            st.info(
                "ℹ️ **SailPoint Identity Governance:** Access changes evaluate directory identities, roles, entitlements, "
                "and SoD conflict policies configured in Section F2 below. Uploading a Terraform file is optional."
            )
            scenario_mode = "SailPoint Identity Governance Parameters"
        else:
            st.markdown("#### Configuration Payload Source")
            scenario_mode = st.radio(
                "Configuration Payload Source:",
                options=["Existing Enterprise Demo Scenario", "Upload Custom Terraform (.tf)"],
                index=0,
                horizontal=True,
            )

            if scenario_mode == "Existing Enterprise Demo Scenario":
                scenario_options = list(scenarios.keys())
                if scenario_options:
                    selected_scenario_key = st.selectbox(
                        "Select Verified Scenario *",
                        options=scenario_options,
                        format_func=lambda k: scenarios[k]["label"],
                    )
                    sc_info = scenarios[selected_scenario_key]
                    st.info(
                        f"**Scenario Context:** {sc_info['description']}  \n"
                        f"**Target:** {sc_info['ci']} | **Platform:** {sc_info['platform']}"
                    )
                else:
                    st.warning("No verified scenario files found in changes/ directory.")
            else:
                st.markdown(
                    """
                    <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 6px;">
                        Upload a valid <code>.tf</code> Terraform configuration file (Max 1MB, plain text only).
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # DOMAIN SPECIFIC SECTION
        # ---------------------------------------------------------------------
        fw_details = FirewallChangeDetails()
        sp_details = SailPointChangeDetails()

        if domain_choice == "Network Security / Firewall":
            st.markdown(
                """
                <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                    <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                        Section F1 — Network Security & Firewall Rule Specifications
                    </h3>
                </div>
                """,
                unsafe_allow_html=True,
            )

            col_fw1, col_fw2 = st.columns(2)
            with col_fw1:
                firewall_platform = st.selectbox(
                    "Firewall Platform",
                    options=[
                        "Palo Alto Networks PA-5450",
                        "AWS VPC Security Group",
                        "Cisco Secure Firewall",
                    ],
                    index=0,
                )
                firewalls = dataset_service.get_firewalls()
                fw_names = [f["name"] for f in firewalls] or ["fw-edge-01-primary"]
                firewall_device = st.selectbox("Firewall Device", options=fw_names, index=0)
                panorama_ref = st.text_input(
                    "Panorama Reference",
                    value="pan-mgmt-01.mgmt.apex-global.example",
                )
                change_op = st.selectbox(
                    "Change Operation",
                    options=["Create", "Modify", "Delete"],
                    index=0,
                )
                rule_name = st.text_input(
                    "Security Policy / Rule Name *",
                    value="Allow-Analytics-Outbound-Webhook",
                )

            with col_fw2:
                zones = dataset_service.get_zones()
                zone_names = [z["name"] for z in zones] or [
                    "Trust-DMZ",
                    "Untrust-Internet",
                    "Corp-Users",
                    "Prod-App-Workloads",
                ]
                src_zone = st.selectbox("Source Zone *", options=zone_names, index=0)
                dst_zone = st.selectbox(
                    "Destination Zone *",
                    options=zone_names,
                    index=1 if len(zone_names) > 1 else 0,
                )
                action = st.selectbox("Rule Action", options=["allow", "deny", "drop"], index=0)
                sec_profile = st.selectbox(
                    "Security Profile Group",
                    options=[
                        "Strict-Enterprise-Security",
                        "Baseline-Inspection",
                        "none",
                    ],
                    index=0,
                )

            col_net1, col_net2 = st.columns(2)
            with col_net1:
                src_addr = st.text_input(
                    "Source Address / CIDR *",
                    value="10.100.4.0/24",
                    help="IP subnet or address object.",
                )
                dst_addr = st.text_input(
                    "Destination Address / CIDR *",
                    value="any",
                    help="Target IP or CIDR scope. Avoid 'any' for outbound egress.",
                )
                app_id = st.text_input(
                    "App-ID (Application) *",
                    value="ssl",
                    help="Palo Alto App-ID (e.g. ssl, web-browsing). Avoid 'any'.",
                )

            with col_net2:
                service = st.text_input("Service", value="service-https")
                protocol = st.selectbox("Protocol", options=["TCP", "UDP", "ICMP", "ANY"], index=0)
                src_port = st.text_input("Source Port", value="any")
                dst_port = st.text_input("Destination Port", value="443")

            fw_details = FirewallChangeDetails(
                firewall_platform=firewall_platform,
                firewall_device=firewall_device,
                panorama_reference=panorama_ref,
                rule_name=rule_name,
                source_zone=src_zone,
                destination_zone=dst_zone,
                source_addresses=src_addr,
                destination_addresses=dst_addr,
                applications=app_id,
                services=service,
                protocol=protocol,
                source_port=src_port,
                destination_port=dst_port,
                action=action,
                security_profile=sec_profile,
                change_operation=change_op,
            )

        else:
            # SailPoint Section
            st.markdown(
                """
                <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                    <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                        Section F2 — SailPoint Identity Governance & Access Change
                    </h3>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Load actual SailPoint data
            identities = dataset_service.get_identities()
            id_options = [
                f"{i['display_name']} ({i['id']} - {i.get('job_title', 'Staff')})"
                for i in identities
            ] or ["Sarah Chen (sp-ident-sarah-chen)"]

            id_profiles = dataset_service.get_identity_profiles()
            idp_options = [p["name"] for p in id_profiles] or ["Corporate Full-Time Employees"]

            sources = dataset_service.get_sources()
            src_options = [s["name"] for s in sources] or ["Corporate Active Directory"]

            roles = dataset_service.get_roles()
            role_options = [f"{r['name']} ({r['id']})" for r in roles] or ["Finance & Treasury Analyst"]

            acc_profiles = dataset_service.get_access_profiles()
            ap_options = [f"{ap['name']} ({ap['id']})" for ap in acc_profiles] or ["Production S3 CUI Vault Read Access"]

            entitlements = dataset_service.get_entitlements()
            ent_options = [f"{e['name']} ({e['id']})" for e in entitlements] or ["AWS Production S3 CUI Vault Read"]

            col_sp1, col_sp2 = st.columns(2)
            with col_sp1:
                st.markdown("##### 👤 Identity Information")
                sel_identity_str = st.selectbox("Target Identity *", options=id_options, index=0)
                sel_idp = st.selectbox("Identity Profile", options=idp_options, index=0)
                sel_src = st.selectbox("Authoritative Source", options=src_options, index=0)
                account_id = st.text_input("Source Account ID", value="sp-acct-ad-sarah-chen")
                account_status = st.selectbox(
                    "Account Status", options=["ACTIVE", "INACTIVE", "LOCKED"], index=0
                )

            with col_sp2:
                st.markdown("##### 🔑 Access Request Scope")
                sel_role = st.selectbox("Requested Role *", options=role_options, index=0)
                sel_ap = st.selectbox("Access Profile", options=ap_options, index=0)
                sel_ent = st.selectbox("Entitlement *", options=ent_options, index=0)
                app_target = st.text_input("Target Application", value="Enterprise AWS Cloud Services")
                expiry_date = st.date_input(
                    "Access Expiry Date (Optional)",
                    value=datetime.now() + timedelta(days=90),
                )

            st.markdown("##### 📋 Governance Lifecycle States")
            col_gov1, col_gov2, col_gov3, col_gov4, col_gov5 = st.columns(5)
            with col_gov1:
                req_status = st.selectbox(
                    "Request Status", options=["SUBMITTED", "PENDING_APPROVAL", "APPROVED"], index=0
                )
            with col_gov2:
                appr_status = st.selectbox(
                    "Approval Status", options=["PENDING", "APPROVED", "REJECTED"], index=0
                )
            with col_gov3:
                prov_status = st.selectbox(
                    "Provisioning Status", options=["UNPROVISIONED", "QUEUED", "PROVISIONED"], index=0
                )
            with col_gov4:
                cert_status = st.selectbox(
                    "Certification", options=["UNCERTIFIED", "CERTIFIED"], index=0
                )
            with col_gov5:
                rev_status = st.selectbox(
                    "Revocation", options=["NONE", "SCHEDULED", "REVOKED"], index=0
                )

            sp_details = SailPointChangeDetails(
                identity_name=sel_identity_str,
                identity_profile=sel_idp,
                identity_source=sel_src,
                account_id=account_id,
                account_status=account_status,
                requested_role=sel_role,
                access_profile=sel_ap,
                entitlement=sel_ent,
                application_name=app_target,
                business_justification=justification,
                access_expiry=str(expiry_date),
                request_status=req_status,
                approval_status=appr_status,
                provisioning_status=prov_status,
                certification_status=cert_status,
                revocation_status=rev_status,
            )

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # SECTION C: PLANNING
        # ---------------------------------------------------------------------
        st.markdown(
            """
            <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                    Section C — Implementation & Operational Planning
                </h3>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_c1, col_c2 = st.columns(2)
        with col_c1:
            impl_plan = st.text_area(
                "Implementation Plan",
                value="Apply candidate Terraform configuration through pre-flight CI/CD deployment pipeline.",
                height=80,
            )
            backout_plan = st.text_area(
                "Backout Plan",
                value="Git revert policy merge request and execute Terraform apply against previous baseline.",
                height=80,
            )
            business_impact = st.text_area(
                "Business Impact Assessment",
                value="Zero expected downtime. Service continues normal operation throughout the maintenance window.",
                height=80,
            )

        with col_c2:
            tech_approach = st.text_area(
                "Technical Approach",
                value="Layer-7 inspection rules deployed via Panorama central device group.",
                height=80,
            )
            validation_plan = st.text_area(
                "Validation Plan",
                value="SimuGuard AI deterministic simulation verification followed by synthetic curl telemetry probe.",
                height=80,
            )
            operational_impact = st.text_area(
                "Operational Impact",
                value="Requires temporary firewall session state synchronization.",
                height=80,
            )

        dependencies = st.text_input(
            "Change Dependencies",
            value="PAN-OS 11.1 Panorama management reachability; IAM role trust relationship.",
        )
        additional_notes = st.text_area("Additional Notes", value="", height=70)

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # SECTION D: SCHEDULE
        # ---------------------------------------------------------------------
        st.markdown(
            """
            <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                    Section D — Change Schedule
                </h3>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_d1, col_d2 = st.columns(2)
        now_dt = datetime.now()
        with col_d1:
            start_date = st.date_input("Planned Start Date *", value=now_dt.date())
            start_time = st.time_input("Planned Start Time *", value=now_dt.time())
            maint_window = st.selectbox(
                "Maintenance Window",
                options=[
                    "Weekend Maintenance Window (Sat 02:00 - 06:00 UTC)",
                    "Weekday Off-Hours (Daily 23:00 - 01:00 UTC)",
                    "Emergency Change (Immediate Execution Window)",
                ],
                index=0,
            )

        with col_d2:
            end_date = st.date_input(
                "Planned End Date *", value=(now_dt + timedelta(hours=4)).date()
            )
            end_time = st.time_input(
                "Planned End Time *", value=(now_dt + timedelta(hours=4)).time()
            )
            scheduling_notes = st.text_input(
                "Scheduling Notes",
                value="Scheduled within standard authorized weekend maintenance window.",
            )

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # SECTION E: INITIAL RISK CONTEXT
        # ---------------------------------------------------------------------
        st.markdown(
            """
            <div style="border-bottom: 2px solid #0f62fe; padding-bottom: 4px; margin-bottom: 1rem;">
                <h3 style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin: 0;">
                    Section E — Initial Risk Context (Requester Assessment)
                </h3>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_e1, col_e2, col_e3 = st.columns(3)
        with col_e1:
            exp_biz = st.selectbox(
                "Expected Business Impact",
                options=["Low", "Medium", "High", "Critical"],
                index=0,
            )
        with col_e2:
            exp_tech = st.selectbox(
                "Expected Technical Impact",
                options=["Low", "Medium", "High", "Critical"],
                index=0,
            )
        with col_e3:
            exp_disrupt = st.selectbox(
                "Expected Service Disruption",
                options=["None", "Minor (Transient)", "Major (Outage Required)"],
                index=0,
            )

        risk_context_notes = st.text_area(
            "Additional Requester Risk Notes",
            value="Standard operational update. SimuGuard AI simulation required before CAB review.",
            height=70,
        )

        st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # ACTION BUTTONS
        # ---------------------------------------------------------------------
        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 3])
        with col_btn1:
            save_draft_clicked = st.form_submit_button(
                "💾 Save Draft", use_container_width=True
            )
        with col_btn2:
            submit_clicked = st.form_submit_button(
                "🚀 Submit Request", use_container_width=True
            )
        with col_btn3:
            cancel_clicked = st.form_submit_button("❌ Cancel", use_container_width=False)

    # Outside form: File uploader if custom upload mode is selected
    uploaded_file_path: Optional[str] = None
    uploaded_content: Optional[str] = None
    if scenario_mode == "Upload Custom Terraform (.tf)":
        st.markdown("#### Upload Terraform File (.tf)")
        up_file = st.file_uploader(
            "Select .tf file", type=["tf"], key="custom_tf_uploader"
        )
        if up_file is not None:
            v_ok, v_msg, st_path, content = validate_and_stage_upload(
                filename=up_file.name, file_bytes=up_file.getvalue()
            )
            if v_ok:
                st.success(f"File validated and staged safely: `{Path(st_path).name}`")
                uploaded_file_path = st_path
                uploaded_content = content
            else:
                st.error(f"Upload validation failed: {v_msg}")

    # =========================================================================
    # FORM SUBMISSION & DRAFT HANDLERS
    # =========================================================================
    if cancel_clicked:
        st.session_state["active_page"] = PAGE_OVERVIEW
        st.rerun()

    if save_draft_clicked or submit_clicked:
        # 1. Validate Schedule
        start_datetime = datetime.combine(start_date, start_time)
        end_datetime = datetime.combine(end_date, end_time)
        if end_datetime <= start_datetime:
            st.error("Validation Error: Planned End Date/Time must be strictly after Planned Start Date/Time.")
            return

        # 2. Validate Required Fields on Submit
        if submit_clicked:
            missing_fields = []
            if not title or not title.strip():
                missing_fields.append("Short Description")
            if not description or not description.strip():
                missing_fields.append("Detailed Description")
            if not justification or not justification.strip():
                missing_fields.append("Business Justification")

            # Check scenario or upload
            if not is_identity_gov:
                if scenario_mode == "Existing Enterprise Demo Scenario":
                    if not selected_scenario_key or selected_scenario_key not in scenarios:
                        missing_fields.append("Valid Enterprise Demo Scenario")
                else:
                    if not uploaded_file_path:
                        missing_fields.append("Valid Staged Terraform (.tf) File")
            else:
                # Validate Identity Governance Fields
                if not sp_details.identity_name or not sp_details.identity_name.strip():
                    missing_fields.append("Target Identity")
                if not (sp_details.requested_role or sp_details.access_profile or sp_details.entitlement):
                    missing_fields.append("At least one Access Grant (Role, Access Profile, or Entitlement)")

            if missing_fields:
                st.error(f"Cannot submit request. Please fill in mandatory fields: {', '.join(missing_fields)}")
                return

        # 3. Determine payload source and content
        source_path: Optional[str] = None
        source_content: Optional[str] = None
        sc_name: Optional[str] = None

        if not is_identity_gov and scenario_mode == "Existing Enterprise Demo Scenario" and selected_scenario_key:
            sc_info = scenarios[selected_scenario_key]
            source_path = sc_info["path"]
            sc_name = selected_scenario_key
            try:
                source_content = Path(source_path).read_text(encoding="utf-8")
            except Exception:
                source_content = ""
        elif uploaded_file_path:
            source_path = uploaded_file_path
            sc_name = Path(uploaded_file_path).name
            source_content = uploaded_content or ""
        elif is_identity_gov:
            source_path = None
            sc_name = f"sailpoint_access_{sp_details.identity_name[:25]}"
            source_content = json.dumps(sp_details.model_dump(), indent=2)

        # Map domain
        dom_enum = (
            ChangeDomain.NETWORK_SECURITY.value
            if "Network" in domain_choice
            else ChangeDomain.IDENTITY_GOVERNANCE.value
        )

        # 4. Construct ChangeRequestRecord
        record = ChangeRequestRecord(
            request_number=request_number,
            title=title.strip() if title else f"Draft Change {request_number}",
            description=description.strip() if description else "Draft description",
            justification=justification.strip(),
            submitted_by=requested_by.strip() or "SecOps Engineer",
            submitter_role=submitter_role.strip() or "Network Security Operations",
            change_type=change_type.upper(),
            domain=dom_enum,
            priority=priority.upper(),
            status=WorkflowState.DRAFT.value if save_draft_clicked else WorkflowState.SUBMITTED.value,
            category=category,
            subcategory=subcategory,
            assignment_group=assignment_group,
            assigned_engineer=assigned_to,
            business_service=business_service,
            configuration_item=config_item,
            affected_application=affected_app,
            infrastructure_platform=infra_platform,
            target_environment=target_env,
            scenario_name=sc_name,
            source_file_path=source_path,
            raw_content=source_content,
            implementation_plan=impl_plan,
            technical_approach=tech_approach,
            backout_plan=backout_plan,
            validation_plan=validation_plan,
            business_impact=business_impact,
            operational_impact=operational_impact,
            dependencies=dependencies,
            additional_notes=additional_notes,
            planned_start=start_datetime.isoformat(),
            planned_end=end_datetime.isoformat(),
            maintenance_window=maint_window,
            scheduling_notes=scheduling_notes,
            expected_business_impact=exp_biz,
            expected_technical_impact=exp_tech,
            expected_service_disruption=exp_disrupt,
            risk_context=risk_context_notes,
            firewall_details_json=fw_details.model_dump_json() if "Network" in domain_choice else None,
            sailpoint_details_json=sp_details.model_dump_json() if "Identity" in domain_choice else None,
        )

        # 5. Persist via repository
        if save_draft_clicked:
            saved = repository.save_draft(record)
            st.success(f"Draft saved successfully for request `{saved.request_number}`.")
        else:
            saved = repository.submit_change_request(record)
            st.success(f"Change Request `{saved.request_number}` submitted successfully!")

        # Reset pre-generated number and navigate to detail page
        del st.session_state["form_request_number"]
        st.session_state["viewing_request_number"] = saved.request_number
        st.session_state["active_page"] = "Record Detail"
        st.rerun()

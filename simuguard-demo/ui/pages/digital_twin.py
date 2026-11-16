"""Digital Twin Explorer Page — interactive graph inspection, topology exploration, and blast-radius analysis."""

import html
import json
from typing import Any, Dict, List, Optional
import streamlit as st

from config.settings import PAGE_NEW_CHANGE, PAGE_RESULTS
from storage.models import ChangeDomain, ChangeRequestRecord
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_metric_card
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header
from ui.services.digital_twin_service import (
    CATEGORY_COLORS,
    CATEGORY_MAPPINGS,
    DigitalTwinService,
)


def render_digital_twin_page(repository: ChangeRepository) -> None:
    """Render the Digital Twin Explorer and Blast-Radius analysis interface."""
    render_page_header(
        title="Digital Twin Explorer",
        description="Topological graph visualization and blast-radius exploration of Apex Global Technologies enterprise infrastructure.",
    )

    dt_service = DigitalTwinService.get_instance()
    metrics = dt_service.get_metrics()

    # 1. Executive Top Metrics Row
    col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
    with col_m1:
        render_metric_card(
            label="Total Active Nodes",
            value=metrics["node_count"],
            hint="Modeled Enterprise Assets",
        )
    with col_m2:
        render_metric_card(
            label="Total Relationships",
            value=metrics["edge_count"],
            hint="Active Directional Edges",
        )
    with col_m3:
        render_metric_card(
            label="Asset Categories",
            value=len(metrics["category_counts"]),
            hint="Operational Domains",
        )
    with col_m4:
        render_metric_card(
            label="Sensitive Assets",
            value=metrics["sensitive_assets_count"],
            hint="CUI, PCI & Key Stores",
        )
    with col_m5:
        render_metric_card(
            label="Firewall Vendor",
            value="PAN-OS 11.1",
            hint=metrics["firewall_vendor"][:24],
        )

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 2. Main Tabbed Navigation
    tab_topo, tab_blast = st.tabs([
        "🌐 Enterprise Estate Topology",
        "💥 Blast-Radius & Candidate Overlay Explorer",
    ])

    # =========================================================================
    # TAB 1: Enterprise Estate Topology
    # =========================================================================
    with tab_topo:
        st.markdown(
            """
            <div style="font-size: 0.92rem; color: #475569; margin-bottom: 1rem;">
                Explore real enterprise assets loaded from the Digital Twin graph (220 verified nodes across 7 categories).
                Filter by category or domain, search by name or identifier, and click any asset to inspect direct dependencies.
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Filter and Search Bar
        col_f1, col_f2, col_f3, col_f4 = st.columns([2, 1.5, 1.5, 1])
        with col_f1:
            search_query = st.text_input(
                "Search Asset Name, ID, or Type",
                placeholder="e.g. fw-edge-01, s3-customer, FinOps, IAM...",
                key="dt_search_query",
            )
        with col_f2:
            category_options = ["ALL"] + list(CATEGORY_COLORS.keys())
            category_filter = st.selectbox(
                "Filter by Category",
                options=category_options,
                index=0,
                key="dt_category_filter",
            )
        with col_f3:
            domain_options = ["ALL", "NETWORK_SECURITY", "IDENTITY_GOVERNANCE"]
            domain_filter = st.selectbox(
                "Filter by Domain",
                options=domain_options,
                index=0,
                key="dt_domain_filter",
            )
        with col_f4:
            max_nodes = st.selectbox(
                "Max Nodes",
                options=[25, 50, 100, 220],
                index=1,
                key="dt_max_nodes",
            )

        # Retrieve filtered nodes
        filtered_nodes = dt_service.search_nodes(
            query=search_query,
            category=category_filter,
            domain=domain_filter,
            limit=int(max_nodes),
        )

        # Center / Focus Asset Selector
        node_choices = ["None (Overview Subgraph)"] + [
            f"{n['id']} | {n['name']} ({n['type']})" for n in filtered_nodes
        ]
        focus_selection = st.selectbox(
            "Center Graph on Specific Asset",
            options=node_choices,
            index=0,
            key="dt_focus_node_selector",
        )

        center_node_id: Optional[str] = None
        if focus_selection != "None (Overview Subgraph)":
            center_node_id = focus_selection.split(" | ")[0].strip()

        st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)

        # Category Color Legend
        legend_items = "".join(
            f'<span style="display:inline-flex; align-items:center; gap:6px; margin-right:14px; font-size:0.8rem; color:#475569;">'
            f'<span style="width:10px; height:10px; border-radius:50%; background-color:{color}; display:inline-block;"></span>'
            f'{cat}</span>'
            for cat, color in CATEGORY_COLORS.items()
        )
        st.markdown(
            f"""
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:8px 12px; margin-bottom:12px; display:flex; flex-wrap:wrap;">
                <span style="font-size:0.8rem; font-weight:600; color:#1e293b; margin-right:12px;">Asset Legend:</span>
                {legend_items}
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Topology SVG Canvas
        col_svg, col_details = st.columns([3, 2])

        with col_svg:
            svg_content = dt_service.generate_topology_svg(
                center_node_id=center_node_id,
                category_filter=category_filter if category_filter != "ALL" else None,
                max_nodes=int(max_nodes),
            )
            st.markdown(
                f"""
                <div class="sg-card" style="padding: 0.5rem; overflow-x: auto;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0.75rem; border-bottom: 1px solid #f1f5f9; margin-bottom: 0.5rem;">
                        <span style="font-weight: 600; font-size: 0.88rem; color: #1e293b;">
                            Topology Graph Canvas {f"— Focused on: {center_node_id}" if center_node_id else "(Overview Layout)"}
                        </span>
                        <span style="font-size: 0.78rem; color: #64748b;">
                            Displaying {len(filtered_nodes)} of {metrics['node_count']} nodes
                        </span>
                    </div>
                    {svg_content}
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_details:
            # Asset Details Pane
            detail_target_id = center_node_id or (filtered_nodes[0]["id"] if filtered_nodes else None)
            if detail_target_id:
                details = dt_service.get_node_details(detail_target_id)
            else:
                details = None

            if details:
                crit = details.get("criticality", "MEDIUM")
                crit_badge = f'<span class="sg-badge sg-badge-block">{crit}</span>' if crit in ("CRITICAL", "HIGH") else f'<span class="sg-badge sg-badge-info">{crit}</span>'
                cat = details.get("category", "General")
                cat_color = details.get("color", "#64748b")

                # In/Out relationship rows
                outgoing_rows = []
                for out in details.get("outgoing_edges", []):
                    blast_cond = f'<br/><span style="color:#b45309; font-size:0.75rem;">Condition: {html.escape(out["blast_condition"])}</span>' if out.get("blast_condition") else ""
                    outgoing_rows.append(
                        f"""
                        <li style="margin-bottom:6px; font-size:0.83rem;">
                            <span style="color:#0f62fe; font-weight:600;">→ {html.escape(out['relationship'])}:</span>
                            <strong>{html.escape(out['target_name'])}</strong>
                            <span style="color:#64748b; font-size:0.75rem;">({html.escape(out['target_type'])})</span>
                            {blast_cond}
                        </li>
                        """
                    )
                out_html = "".join(outgoing_rows) if outgoing_rows else '<li style="color:#94a3b8; font-size:0.82rem;">None (leaf / edge node)</li>'

                incoming_rows = []
                for inc in details.get("incoming_edges", []):
                    blast_cond = f'<br/><span style="color:#b45309; font-size:0.75rem;">Condition: {html.escape(inc["blast_condition"])}</span>' if inc.get("blast_condition") else ""
                    incoming_rows.append(
                        f"""
                        <li style="margin-bottom:6px; font-size:0.83rem;">
                            <span style="color:#10b981; font-weight:600;">← {html.escape(inc['relationship'])}:</span>
                            <strong>{html.escape(inc['source_name'])}</strong>
                            <span style="color:#64748b; font-size:0.75rem;">({html.escape(inc['source_type'])})</span>
                            {blast_cond}
                        </li>
                        """
                    )
                inc_html = "".join(incoming_rows) if incoming_rows else '<li style="color:#94a3b8; font-size:0.82rem;">None (root node)</li>'

                # Metadata items
                meta_rows = []
                for k, v in details.get("metadata", {}).items():
                    if v is not None and str(v) != "":
                        val_str = str(v)
                        if len(val_str) > 40:
                            val_str = val_str[:37] + "..."
                        meta_rows.append(
                            f"""
                            <div style="display:flex; justify-content:space-between; font-size:0.8rem; padding:3px 0; border-bottom:1px solid #f8fafc;">
                                <span style="color:#64748b; font-weight:500;">{html.escape(k)}</span>
                                <span style="color:#1e293b; font-family:monospace; font-size:0.78rem;">{html.escape(val_str)}</span>
                            </div>
                            """
                        )
                meta_html = "".join(meta_rows) if meta_rows else '<div style="color:#94a3b8; font-size:0.8rem;">No custom metadata</div>'

                st.markdown(
                    f"""
                    <div class="sg-card">
                        <div class="sg-card-header">
                            <div>
                                <span style="font-weight:700; color:#0f172a; font-size:0.95rem;">{html.escape(details['name'])}</span>
                                <div style="font-size:0.78rem; font-family:monospace; color:#64748b;">ID: {html.escape(details['id'])}</div>
                            </div>
                            <div>{crit_badge}</div>
                        </div>

                        <div style="padding:0.75rem 0; border-bottom:1px solid #f1f5f9;">
                            <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                                <span style="width:10px; height:10px; border-radius:50%; background-color:{cat_color}; display:inline-block;"></span>
                                <span style="font-size:0.85rem; font-weight:600; color:#334155;">{html.escape(cat)}</span>
                                <span style="color:#94a3b8; font-size:0.78rem;">•</span>
                                <span style="font-size:0.82rem; color:#64748b;">{html.escape(details['type'])}</span>
                            </div>
                            <div style="font-size:0.82rem; color:#475569;">
                                Total Connected Relationships: <strong>{details['total_relationships']}</strong>
                            </div>
                        </div>

                        <div style="padding:0.75rem 0; border-bottom:1px solid #f1f5f9;">
                            <div style="font-size:0.82rem; font-weight:700; color:#1e293b; text-transform:uppercase; margin-bottom:6px;">
                                Outgoing Dependencies ({len(details.get('outgoing_edges', []))})
                            </div>
                            <ul style="margin:0; padding-left:1.1rem; line-height:1.5;">
                                {out_html}
                            </ul>
                        </div>

                        <div style="padding:0.75rem 0; border-bottom:1px solid #f1f5f9;">
                            <div style="font-size:0.82rem; font-weight:700; color:#1e293b; text-transform:uppercase; margin-bottom:6px;">
                                Incoming Dependencies ({len(details.get('incoming_edges', []))})
                            </div>
                            <ul style="margin:0; padding-left:1.1rem; line-height:1.5;">
                                {inc_html}
                            </ul>
                        </div>

                        <div style="padding-top:0.75rem;">
                            <div style="font-size:0.82rem; font-weight:700; color:#1e293b; text-transform:uppercase; margin-bottom:6px;">
                                Asset Properties & Configuration
                            </div>
                            {meta_html}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div class="sg-card" style="text-align:center; padding:2rem 1rem; color:#64748b;">
                        <div style="font-size:1.8rem; margin-bottom:0.5rem;">🔍</div>
                        <div style="font-weight:600; color:#1e293b;">No Asset Selected</div>
                        <div style="font-size:0.85rem;">Select an asset from the list to inspect its properties.</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Asset Search Table
        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Active Digital Twin Node Inventory</span>
                    <span style="font-size: 0.8rem; color: #64748b;">Showing {len(filtered_nodes)} assets</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if filtered_nodes:
            table_rows = []
            for item in filtered_nodes:
                c_badge = (
                    f'<span class="sg-badge sg-badge-block">{item["criticality"]}</span>'
                    if item["criticality"] in ("CRITICAL", "HIGH")
                    else f'<span class="sg-badge sg-badge-neutral">{item["criticality"]}</span>'
                )
                dot = f'<span style="width:8px; height:8px; border-radius:50%; background-color:{item["color"]}; display:inline-block; margin-right:6px;"></span>'
                table_rows.append(
                    f"""
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding:8px; font-family:monospace; font-weight:600; color:#0f62fe;">{html.escape(item['id'])}</td>
                        <td style="padding:8px; font-weight:500; color:#1e293b;">{html.escape(item['name'])}</td>
                        <td style="padding:8px; font-size:0.82rem; color:#64748b;">{html.escape(item['type'])}</td>
                        <td style="padding:8px; font-size:0.82rem; color:#334155;">{dot}{html.escape(item['category'])}</td>
                        <td style="padding:8px;">{c_badge}</td>
                        <td style="padding:8px; font-size:0.82rem; text-align:center; font-weight:600;">{item['degree']}</td>
                    </tr>
                    """
                )

            st.markdown(
                f"""
                <div style="overflow-x:auto; background:#ffffff; border:1px solid #e2e8f0; border-radius:6px;">
                    <table style="width:100%; border-collapse:collapse; font-size:0.85rem; text-align:left;">
                        <thead>
                            <tr style="background:#f8fafc; border-bottom:2px solid #e2e8f0; color:#475569; font-size:0.75rem; text-transform:uppercase;">
                                <th style="padding:10px 8px;">Asset Identifier</th>
                                <th style="padding:10px 8px;">Asset Name</th>
                                <th style="padding:10px 8px;">Asset Type</th>
                                <th style="padding:10px 8px;">Operational Category</th>
                                <th style="padding:10px 8px;">Criticality</th>
                                <th style="padding:10px 8px; text-align:center;">Degrees</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(table_rows)}
                        </tbody>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # =========================================================================
    # TAB 2: Blast-Radius & Candidate Overlay Explorer
    # =========================================================================
    with tab_blast:
        st.markdown(
            """
            <div style="font-size: 0.92rem; color: #475569; margin-bottom: 1rem;">
                Inspect blast-radius propagation and candidate overlay topology modifications for simulated Change Requests.
                Evaluate directly affected assets, cascading dependencies, sensitive data stores (CUI / PCI), and candidate overlay changes.
            </div>
            """,
            unsafe_allow_html=True,
        )

        all_requests = repository.list_change_requests(limit=100)
        assessed_requests = [
            r for r in all_requests if repository.get_latest_assessment(r.request_number) is not None
        ]

        if not assessed_requests:
            st.markdown(
                """
                <div class="sg-empty-state">
                    <div style="font-size: 2.2rem;">💥</div>
                    <div class="sg-empty-title">No Assessed Change Requests Found</div>
                    <div class="sg-empty-subtitle">
                        Run a pre-flight simulation on a Change Request to explore its blast-radius and candidate overlay.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            col_b1, col_b2, col_b3 = st.columns([1, 1, 1])
            with col_b2:
                if st.button("Submit New Change Request →", use_container_width=True, key="btn_dt_to_new_change"):
                    st.session_state["active_page"] = PAGE_NEW_CHANGE
                    st.rerun()
            return

        # Selector for Assessed Change Requests
        req_options = [r.request_number for r in assessed_requests]
        active_req_no = st.session_state.get("viewing_request_number")
        current_idx = req_options.index(active_req_no) if active_req_no in req_options else 0

        col_sel1, col_sel2 = st.columns([3, 1])
        with col_sel1:
            selected_req_no = st.selectbox(
                "Select Change Request to Inspect Blast Radius",
                options=req_options,
                index=current_idx,
                format_func=lambda x: f"{x} — {next((r.title for r in assessed_requests if r.request_number == x), '')}",
                key="dt_blast_req_selector",
            )
            st.session_state["viewing_request_number"] = selected_req_no

        with col_sel2:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("📊 View Assessment Results →", use_container_width=True, key="btn_dt_to_results"):
                st.session_state["active_page"] = PAGE_RESULTS
                st.rerun()

        # Load Assessment and Remediation Data
        selected_record = next(r for r in assessed_requests if r.request_number == selected_req_no)
        assessment = repository.get_latest_assessment(selected_req_no)
        remediation = repository.get_latest_remediation(selected_req_no)

        raw_asmt: Dict[str, Any] = {}
        if assessment and assessment.raw_json:
            try:
                raw_asmt = json.loads(assessment.raw_json)
            except Exception:
                pass

        affected_assets = raw_asmt.get("predicted_affected_assets", [])
        direct_impacts = [a for a in affected_assets if a.get("blast_tier") == "DIRECT" or a.get("tier") == "DIRECT"]
        cascading_impacts = [a for a in affected_assets if a.get("blast_tier") == "CASCADING" or a.get("tier") == "CASCADING"]
        sensitive_impacts = [
            a for a in affected_assets
            if a.get("criticality") in ("CRITICAL", "HIGH")
            or "CUI" in str(a.get("impact_description", ""))
            or "PCI" in str(a.get("impact_description", ""))
            or "Vault" in str(a.get("asset_name", ""))
        ]

        # Blast Radius Metrics
        st.markdown("<div style='height: 0.75rem;'></div>", unsafe_allow_html=True)
        col_br1, col_br2, col_br3, col_br4 = st.columns(4)
        with col_br1:
            render_metric_card(
                label="Directly Affected",
                value=f"{len(direct_impacts)} Nodes",
                hint="Trigger Asset Scope",
            )
        with col_br2:
            render_metric_card(
                label="Cascading Impacts",
                value=f"{len(cascading_impacts)} Nodes",
                hint="Transitive Dependencies",
            )
        with col_br3:
            render_metric_card(
                label="Sensitive Data Stores",
                value=f"{len(sensitive_impacts)} Assets",
                hint="CUI / PCI / Vault Exposure",
            )
        with col_br4:
            render_metric_card(
                label="Total Blast Traversal",
                value=f"{len(affected_assets)} Assets",
                hint="Total Impact Footprint",
            )

        st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

        # Blast Radius Asset Table
        col_tbl, col_overlay = st.columns([3, 2])

        with col_tbl:
            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">
                        <span>Traversed Blast Radius Assets</span>
                        <span style="font-size:0.8rem; color:#64748b;">Request: {selected_req_no}</span>
                    </div>
                """,
                unsafe_allow_html=True,
            )

            if affected_assets:
                asset_rows = []
                for a in affected_assets:
                    tier = a.get("blast_tier") or a.get("tier", "DIRECT")
                    if tier == "DIRECT":
                        t_badge = '<span class="sg-badge sg-badge-block">DIRECT</span>'
                    elif tier == "CASCADING":
                        t_badge = '<span class="sg-badge sg-badge-warn">CASCADING</span>'
                    else:
                        t_badge = '<span class="sg-badge sg-badge-purple">UNKNOWN</span>'

                    crit = a.get("criticality", "HIGH")
                    c_badge = (
                        f'<span class="sg-badge sg-badge-block">{crit}</span>'
                        if crit in ("CRITICAL", "HIGH")
                        else f'<span class="sg-badge sg-badge-neutral">{crit}</span>'
                    )

                    desc = a.get("impact_description") or a.get("reason_affected", "Affected by policy change")

                    asset_rows.append(
                        f"""
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding:8px; font-family:monospace; font-weight:600; color:#0f62fe;">{html.escape(str(a.get('asset_id', '')))}</td>
                            <td style="padding:8px; font-weight:500; color:#1e293b;">{html.escape(str(a.get('asset_name', '')))}</td>
                            <td style="padding:8px; font-size:0.8rem; color:#64748b;">{html.escape(str(a.get('asset_type', '')))}</td>
                            <td style="padding:8px;">{t_badge}</td>
                            <td style="padding:8px;">{c_badge}</td>
                            <td style="padding:8px; font-size:0.8rem; color:#475569;">{html.escape(desc)}</td>
                        </tr>
                        """
                    )

                st.markdown(
                    f"""
                    <div style="overflow-x:auto;">
                        <table style="width:100%; border-collapse:collapse; font-size:0.84rem; text-align:left;">
                            <thead>
                                <tr style="background:#f8fafc; border-bottom:2px solid #e2e8f0; color:#475569; font-size:0.75rem; text-transform:uppercase;">
                                    <th style="padding:8px;">Asset ID</th>
                                    <th style="padding:8px;">Asset Name</th>
                                    <th style="padding:8px;">Type</th>
                                    <th style="padding:8px;">Blast Tier</th>
                                    <th style="padding:8px;">Criticality</th>
                                    <th style="padding:8px;">Impact Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {"".join(asset_rows)}
                            </tbody>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div style="padding:1.5rem; text-align:center; color:#10b981; font-weight:600;">
                        ✓ Zero external infrastructure assets exposed. Blast radius is strictly isolated.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("</div>", unsafe_allow_html=True)

        with col_overlay:
            # Candidate Overlay Topology Modifications
            raw_comp: Dict[str, Any] = {}
            if remediation and remediation.comparison_json:
                try:
                    raw_comp = json.loads(remediation.comparison_json)
                except Exception:
                    pass

            st.markdown(
                f"""
                <div class="sg-card">
                    <div class="sg-card-header">
                        <span>Candidate Digital Twin Overlay Modifications</span>
                        <span class="sg-badge sg-badge-info">Overlay Isolation</span>
                    </div>
                    <div style="font-size:0.85rem; color:#475569; margin-bottom:0.75rem; line-height:1.5;">
                        SimuGuard evaluates automated remediations by applying non-destructive candidate overlays over the base topology without mutating the live model.
                    </div>
                """,
                unsafe_allow_html=True,
            )

            if remediation:
                resolved_count = raw_comp.get("resolved_count", 0)
                score_before = raw_comp.get("risk_score_before", assessment.composite_risk_score if assessment else 0.0)
                score_after = raw_comp.get("risk_score_after", 0.0)
                delta = raw_comp.get("risk_score_delta", score_before - score_after)

                st.markdown(
                    f"""
                    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:10px 12px; margin-bottom:12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.82rem; font-weight:600; color:#475569;">Risk Score Reduction:</span>
                            <span style="font-size:0.95rem; font-weight:700; color:#10b981;">-{delta:.1f} pts ({score_before:.1f} → {score_after:.1f})</span>
                        </div>
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:0.82rem; font-weight:600; color:#475569;">Gaps Resolved:</span>
                            <span style="font-size:0.85rem; font-weight:700; color:#0f62fe;">{resolved_count} Security Gaps Remediated</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Topology Edge Modifications
                st.markdown(
                    """
                    <div style="margin-bottom:8px; font-size:0.82rem; font-weight:700; color:#1e293b; text-transform:uppercase;">
                        Candidate Overlay Graph Operations
                    </div>
                    <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:10px 12px; font-size:0.82rem; line-height:1.6;">
                        <div style="margin-bottom:8px;">
                            <strong style="color:#ef4444;">✕ Severed Overly-Permissive Edges:</strong>
                            <ul style="margin:4px 0 8px 1rem; padding:0; color:#475569;">
                                <li>Pruned unrestricted egress/ingress paths to wildcards (<code>0.0.0.0/0</code>).</li>
                                <li>Detached unapproved privilege escalation paths.</li>
                            </ul>
                        </div>
                        <div>
                            <strong style="color:#10b981;">✓ Synthesized Compliant Controls:</strong>
                            <ul style="margin:4px 0 0 1rem; padding:0; color:#475569;">
                                <li>Enforced explicit App-ID traffic inspection profiles.</li>
                                <li>Bound access strictly to designated CIDR blocks and SoD approval workflows.</li>
                            </ul>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div style="padding:1.5rem; text-align:center; color:#64748b; font-size:0.85rem;">
                        No automated remediation overlay synthesized yet for this Change Request.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("</div>", unsafe_allow_html=True)

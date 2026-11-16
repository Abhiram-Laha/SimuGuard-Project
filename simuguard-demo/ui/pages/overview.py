"""Overview Page: Executive Security & Change Risk Dashboard."""

import altair as alt
import pandas as pd
import streamlit as st

from config.settings import PAGE_NEW_CHANGE
from storage.repository import ChangeRepository
from ui.components.metric_cards import render_kpi_row
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header


def render_overview_page(repository: ChangeRepository) -> None:
    """Render the executive change risk overview dashboard."""
    render_page_header(
        title="Security Change Risk Overview",
        description="Continuous pre-deployment change assessment and automated remediation for Apex Global enterprise infrastructure.",
        action_button=True,
        button_label="➕ New Change Request",
    )

    # 1. Executive KPI Summary Row
    kpis = repository.get_kpi_summary()
    render_kpi_row(kpis)

    st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

    # 2. Charts and Analytics Section
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown(
            """
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Gate Verdict Distribution</span>
                    <span style="font-size: 0.78rem; color: #64748b; font-weight: 400;">Pre-flight decisions</span>
                </div>
            """,
            unsafe_allow_html=True,
        )

        if kpis.total_requests > 0 and (kpis.allowed_count + kpis.warn_count + kpis.blocked_count) > 0:
            chart_data = pd.DataFrame(
                [
                    {"Verdict": "ALLOW", "Count": kpis.allowed_count, "Color": "#10b981"},
                    {"Verdict": "WARN", "Count": kpis.warn_count, "Color": "#f59e0b"},
                    {"Verdict": "BLOCK", "Count": kpis.blocked_count, "Color": "#ef4444"},
                ]
            )
            # Filter out zero counts for clean display
            chart_data = chart_data[chart_data["Count"] > 0]

            chart = (
                alt.Chart(chart_data)
                .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                .encode(
                    x=alt.X("Verdict:N", title=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("Count:Q", title="Requests", axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color("Color:N", scale=None, legend=None),
                    tooltip=["Verdict", "Count"],
                )
                .properties(height=220)
            )
            st.altair_chart(chart, use_container_width=True)
        else:
            st.markdown(
                """
                <div class="sg-empty-state" style="padding: 2.2rem 1rem;">
                    <div style="font-size: 1.8rem;">📊</div>
                    <div class="sg-empty-title">No Simulation Verdicts Yet</div>
                    <div class="sg-empty-subtitle">
                        Deployment decisions (ALLOW, WARN, BLOCK) will appear here once Terraform changes are analyzed.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    with col_chart2:
        st.markdown(
            """
            <div class="sg-card">
                <div class="sg-card-header">
                    <span>Remediation & Risk Trend</span>
                    <span style="font-size: 0.78rem; color: #64748b; font-weight: 400;">Closed-loop effectiveness</span>
                </div>
            """,
            unsafe_allow_html=True,
        )

        if kpis.total_requests > 0:
            trend_data = pd.DataFrame(
                [
                    {"Metric": "Assessed", "Value": kpis.total_requests, "Color": "#3b82f6"},
                    {"Metric": "Blocked", "Value": kpis.blocked_count, "Color": "#ef4444"},
                    {"Metric": "Remediated", "Value": kpis.remediated_count, "Color": "#10b981"},
                ]
            )
            chart2 = (
                alt.Chart(trend_data)
                .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                .encode(
                    x=alt.X("Metric:N", title=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("Value:Q", title="Volume", axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color("Color:N", scale=None, legend=None),
                    tooltip=["Metric", "Value"],
                )
                .properties(height=220)
            )
            st.altair_chart(chart2, use_container_width=True)
        else:
            st.markdown(
                """
                <div class="sg-empty-state" style="padding: 2.2rem 1rem;">
                    <div style="font-size: 1.8rem;">📈</div>
                    <div class="sg-empty-title">No Risk Trend Data</div>
                    <div class="sg-empty-subtitle">
                        Automated candidate fixes and post-remediation risk reduction metrics will populate this chart.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 3. Recent Change Requests Table
    st.markdown(
        """
        <div class="sg-card">
            <div class="sg-card-header">
                <span>Recent Change Requests & Assessments</span>
                <span style="font-size: 0.78rem; color: #64748b; font-weight: 400;">Last 10 submissions</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    recent = repository.get_recent_assessments(limit=10)

    if recent:
        # Build HTML table for crisp enterprise look
        table_rows = []
        for r in recent:
            req_no = r.get("request_number", "")
            title = r.get("title", "")
            prio_badge = render_priority_badge(r.get("priority", "NORMAL"))
            status_badge = render_workflow_badge(r.get("status", "SUBMITTED"))
            verdict_badge = render_verdict_badge(r.get("verdict"))
            score = r.get("composite_risk_score")
            score_badge = render_risk_score_badge(score) if score is not None else '<span style="color:#94a3b8;">-</span>'
            gaps = r.get("security_gaps_count")
            gaps_str = f"{gaps} gaps" if gaps is not None else "-"
            blast = r.get("blast_radius_nodes_count")
            blast_str = f"{blast} nodes" if blast is not None else "-"

            table_rows.append(
                f"""
                <tr>
                    <td style="font-weight:600; font-family:monospace; color:#0f62fe;">{req_no}</td>
                    <td style="font-weight:500;">{title}</td>
                    <td>{prio_badge}</td>
                    <td>{verdict_badge}</td>
                    <td>{score_badge}</td>
                    <td>{status_badge}</td>
                    <td style="color:#64748b; font-size:0.82rem;">{gaps_str} / {blast_str}</td>
                </tr>
                """
            )

        table_html = f"""
        <table style="width:100%; border-collapse:collapse; font-size:0.88rem; text-align:left;">
            <thead>
                <tr style="border-bottom: 2px solid #e2e8f0; color:#475569; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.04em;">
                    <th style="padding:10px 8px;">Request #</th>
                    <th style="padding:10px 8px;">Title</th>
                    <th style="padding:10px 8px;">Priority</th>
                    <th style="padding:10px 8px;">Verdict</th>
                    <th style="padding:10px 8px;">Risk Score</th>
                    <th style="padding:10px 8px;">Status</th>
                    <th style="padding:10px 8px;">Impact</th>
                </tr>
            </thead>
            <tbody>
                {"".join(table_rows)}
            </tbody>
        </table>
        """
        st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.markdown(
            """
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">📋</div>
                <div class="sg-empty-title">No Change Requests in Local Database</div>
                <div class="sg-empty-subtitle">
                    There are no recorded change requests in the local database.
                    Click below to open the change request intake form or inspect the Digital Twin.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_b1, col_b2, col_b3 = st.columns([1, 1, 1])
        with col_b2:
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            if st.button("➕ Submit First Change Request", use_container_width=True):
                st.session_state["active_page"] = PAGE_NEW_CHANGE
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

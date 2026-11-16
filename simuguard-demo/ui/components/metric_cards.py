"""Metric card components for KPI rendering."""

from typing import Any, Optional
import streamlit as st
from storage.models import KPISummary


def render_metric_card(label: str, value: Any, hint: Optional[str] = None) -> None:
    """Render a styled ServiceNow-style metric card."""
    hint_html = f'<div class="sg-metric-hint">{hint}</div>' if hint else ""
    card_html = f"""
    <div class="sg-metric-card">
        <div class="sg-metric-label">{label}</div>
        <div class="sg-metric-value">{value}</div>
        {hint_html}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_kpi_row(kpis: KPISummary) -> None:
    """Render the top executive KPI summary cards row with all 6 core metrics."""
    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        render_metric_card(
            label="Total Changes",
            value=kpis.total_requests,
            hint="Recorded requests",
        )

    with col2:
        render_metric_card(
            label="Blocked Changes",
            value=kpis.blocked_count,
            hint="Deployment blocked",
        )

    with col3:
        render_metric_card(
            label="Manual Review",
            value=kpis.warn_count,
            hint="Requires CAB review",
        )

    with col4:
        render_metric_card(
            label="Approved / Safe",
            value=kpis.allowed_count,
            hint="Zero critical findings",
        )

    with col5:
        render_metric_card(
            label="Auto-Remediated",
            value=kpis.remediated_count,
            hint="Closed-loop verified",
        )

    with col6:
        score_display = f"{kpis.avg_risk_score:.1f}" if kpis.total_requests > 0 else "0.0"
        render_metric_card(
            label="Avg Risk Score",
            value=f"{score_display}/100",
            hint="Pre-flight baseline",
        )

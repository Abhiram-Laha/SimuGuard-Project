"""Navigation router and page dispatchers for SimuGuard AI."""

import streamlit as st
from config.settings import (
    APP_VERSION,
    PAGE_ABOUT,
    PAGE_COMPARISON,
    PAGE_DIGITAL_TWIN,
    PAGE_HISTORY,
    PAGE_NEW_CHANGE,
    PAGE_OVERVIEW,
    PAGE_REMEDIATION,
    PAGE_REPORTS,
    PAGE_RESULTS,
)
from storage.repository import ChangeRepository
from ui.layout import render_page_header
from ui.pages.history import render_history_page
from ui.pages.new_change import render_new_change_page
from ui.pages.overview import render_overview_page
from ui.pages.record_detail import render_record_detail_page


def _render_placeholder_page(title: str, description: str, milestone_phase: str, details: str) -> None:
    """Render an enterprise placeholder card for unbuilt routes."""
    render_page_header(title=title, description=description)

    st.markdown(
        f"""
        <div class="sg-card">
            <div class="sg-card-header">
                <span>{title}</span>
                <span class="sg-badge sg-badge-info">{milestone_phase}</span>
            </div>
            <div style="padding: 1rem 0;">
                <p style="color: #334155; font-size: 0.95rem; line-height: 1.6;">
                    {details}
                </p>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 1rem; margin-top: 1rem;">
                    <div style="font-size: 0.82rem; font-weight: 600; color: #475569; text-transform: uppercase; margin-bottom: 0.5rem;">
                        Planned Functionality
                    </div>
                    <ul style="color: #64748b; font-size: 0.88rem; margin: 0; padding-left: 1.25rem; line-height: 1.6;">
                        <li>Integration with SimuGuard AI simulation core.</li>
                        <li>Local persistence via SQLite repository.</li>
                        <li>Deterministic analysis and real-time validation.</li>
                    </ul>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("← Return to Overview", key=f"btn_return_{title}"):
        st.session_state["active_page"] = PAGE_OVERVIEW
        st.rerun()


def route_page(active_page: str, repository: ChangeRepository) -> None:
    """Dispatch view rendering based on active page selection."""
    if active_page == "Record Detail":
        render_record_detail_page(repository)

    elif active_page == PAGE_OVERVIEW:
        render_overview_page(repository)

    elif active_page == PAGE_NEW_CHANGE:
        render_new_change_page(repository)

    elif active_page == PAGE_HISTORY:
        render_history_page(repository)

    elif active_page == PAGE_RESULTS:
        _render_placeholder_page(
            title="Simulation Assessment Results",
            description="Deep inspection of security findings, blast radius impact, and risk score breakdown.",
            milestone_phase="Milestone D",
            details="Comprehensive pre-deployment analysis displaying gate verdicts (ALLOW, WARN, BLOCK), individual security gap findings, affected digital twin topology nodes, and deterministic risk scoring.",
        )

    elif active_page == PAGE_REMEDIATION:
        _render_placeholder_page(
            title="Remediation Center",
            description="Automated candidate policy synthesis and correction review.",
            milestone_phase="Milestone D",
            details="Inspect auto-generated remediated Terraform policies addressing identified firewall, IAM, and SailPoint violations. Compare original vs candidate configurations before validation.",
        )

    elif active_page == PAGE_COMPARISON:
        _render_placeholder_page(
            title="Before & After Validation Comparison",
            description="Closed-loop verification and risk reduction differential.",
            milestone_phase="Milestone D",
            details="Side-by-side comparison of pre-remediation vs post-remediation security gaps, risk score delta, and residual operational warnings.",
        )

    elif active_page == PAGE_DIGITAL_TWIN:
        _render_placeholder_page(
            title="Digital Twin Explorer",
            description="Interactive graph inspection of Apex Global Technologies infrastructure.",
            milestone_phase="Milestone E",
            details="Explore 220 active enterprise nodes and 77 relationships, including Palo Alto firewalls, Panorama device groups, AWS accounts, SailPoint identities, roles, and business workloads.",
        )

    elif active_page == PAGE_REPORTS:
        _render_placeholder_page(
            title="Reports & Compliance Exports",
            description="Generate executive PDF reports and JSON artifacts for ITSM audit trails.",
            milestone_phase="Milestone E",
            details="Export structured PDF reports suitable for Change Advisory Board (CAB) reviews and compliance documentation, matching enterprise ITSM standards.",
        )

    elif active_page == PAGE_ABOUT:
        _render_placeholder_page(
            title="Settings & System Information",
            description=f"SimuGuard AI Engine v{APP_VERSION} operational metadata.",
            milestone_phase="Milestone E",
            details="System diagnostic settings, local database path inspection, digital twin dataset status, and rule engine configuration.",
        )

    else:
        # Fallback to Overview
        render_overview_page(repository)

"""Navigation router and page dispatchers for SimuGuard AI."""

import streamlit as st
from config.settings import (
    APP_VERSION,
    PAGE_ABOUT,
    PAGE_COMPARISON,
    PAGE_DIGITAL_TWIN,
    PAGE_HISTORY,
    PAGE_NEW_ASSESSMENT,
    PAGE_NEW_CHANGE,
    PAGE_OVERVIEW,
    PAGE_REMEDIATION,
    PAGE_REPORTS,
    PAGE_RESULTS,
    PAGE_SETTINGS,
)
from storage.repository import ChangeRepository
from ui.layout import render_page_header
from ui.pages.comparison import render_comparison_page
from ui.pages.diagnostics import render_diagnostics_page
from ui.pages.digital_twin import render_digital_twin_page
from ui.pages.history import render_history_page
from ui.pages.new_change import render_new_change_page
from ui.pages.overview import render_overview_page
from ui.pages.record_detail import render_record_detail_page
from ui.pages.remediation import render_remediation_page
from ui.pages.reports import render_reports_page
from ui.pages.results import render_results_page
from ui.pages.workspace import render_single_workspace_page


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

    if st.button("← Return to Assessment", key=f"btn_return_{title}"):
        st.session_state["active_page"] = PAGE_NEW_ASSESSMENT
        st.rerun()


def route_page(active_page: str, repository: ChangeRepository) -> None:
    """Dispatch view rendering based on active page selection."""
    if active_page == "Record Detail":
        render_record_detail_page(repository)

    elif active_page == PAGE_NEW_ASSESSMENT:
        render_single_workspace_page(repository)

    elif active_page == PAGE_NEW_CHANGE:
        render_single_workspace_page(repository)

    elif active_page == PAGE_HISTORY:
        render_history_page(repository)

    elif active_page == PAGE_REPORTS or active_page == "Reports & Exports":
        render_reports_page(repository)

    elif active_page == PAGE_SETTINGS or active_page == PAGE_ABOUT:
        render_diagnostics_page(repository)

    elif active_page == PAGE_OVERVIEW:
        render_overview_page(repository)

    elif active_page == PAGE_RESULTS:
        render_results_page(repository)

    elif active_page == PAGE_REMEDIATION:
        render_remediation_page(repository)

    elif active_page == PAGE_COMPARISON:
        render_comparison_page(repository)

    elif active_page == PAGE_DIGITAL_TWIN:
        render_digital_twin_page(repository)

    else:
        # Fallback to New Assessment (primary workspace)
        render_single_workspace_page(repository)

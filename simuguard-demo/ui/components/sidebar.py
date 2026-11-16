"""Sidebar navigation component for SimuGuard AI dashboard."""

import streamlit as st
from config.settings import (
    APP_TITLE,
    APP_VERSION,
    NAV_PAGES,
    PAGE_HISTORY,
    PAGE_NEW_ASSESSMENT,
    PAGE_REPORTS,
    PAGE_SETTINGS,
)

PAGE_ICONS = {
    "New Assessment": "⚡",
    "Assessment History": "📋",
    "Reports": "📄",
    "Settings & Diagnostics": "⚙️",
    # Backward-compatible icon fallbacks
    "Overview": "📊",
    "New Change Request": "➕",
    "Assessment Results": "🔍",
    "Remediation Center": "🛠️",
    "Before & After Comparison": "⚖️",
    "Digital Twin Explorer": "🌐",
    "Reports & Exports": "📄",
    "Settings / About": "⚙️",
}


def render_sidebar() -> str:
    """Render the simplified dark navy sidebar and return the selected page key."""
    with st.sidebar:
        # Branding Header
        st.markdown(
            f"""
            <div class="sg-sidebar-header">
                <div class="sg-sidebar-title">
                    <span>🛡️</span> {APP_TITLE}
                </div>
                <div class="sg-sidebar-subtitle">
                    Enterprise Change Risk Engine
                </div>
                <div style="margin-top: 8px; font-size: 0.72rem; color: #10b981; display: flex; align-items: center; gap: 5px;">
                    <span style="height: 7px; width: 7px; background-color: #10b981; border-radius: 50%; display: inline-block;"></span>
                    Digital Twin: Apex Global (Online)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Current page resolution
        if "active_page" not in st.session_state:
            st.session_state["active_page"] = PAGE_NEW_ASSESSMENT

        current_page = st.session_state["active_page"]
        radio_idx = NAV_PAGES.index(current_page) if current_page in NAV_PAGES else 0

        def _format_func(page_name: str) -> str:
            icon = PAGE_ICONS.get(page_name, "•")
            return f"{icon}  {page_name}"

        st.markdown(
            """
            <div style="font-size:0.72rem; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; margin: 10px 0 4px 2px;">
                Workspace Navigation
            </div>
            """,
            unsafe_allow_html=True,
        )

        selected = st.radio(
            label="Workspace Navigation",
            options=NAV_PAGES,
            index=radio_idx,
            format_func=_format_func,
            key="nav_radio_selection",
            label_visibility="collapsed",
        )

        if current_page in NAV_PAGES:
            st.session_state["active_page"] = selected
        else:
            # If in a sub-view (like Record Detail), update active_page only if user picks a different page
            if selected != PAGE_HISTORY:
                st.session_state["active_page"] = selected

        # Guided Tour Quick Toggle
        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
        st.checkbox(
            "Show Guided Demo Tour",
            value=st.session_state.get("show_guided_tour", True),
            key="show_guided_tour",
            help="Display step-by-step guidance cards across workspace and assessment results.",
        )

        # Quick Mode Indicator (Read-only status in sidebar; modification moved to Settings & Diagnostics)
        current_env = st.session_state.get("environment_mode", "DEMO")
        if current_env == "DEMO":
            st.markdown(
                """
                <div style="background-color: #1e293b; border-radius: 6px; padding: 8px 10px; margin-top: 10px; border: 1px solid #334155;">
                    <div style="font-size: 0.72rem; color: #10b981; font-weight: 600; display: flex; align-items: center; gap: 4px;">
                        <span>🛡️</span> Demo Sandbox Mode
                    </div>
                    <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">
                        DB: <code>simuguard_demo.db</code> (Protected)
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div style="background-color: #1e293b; border-radius: 6px; padding: 8px 10px; margin-top: 10px; border: 1px solid #334155;">
                    <div style="font-size: 0.72rem; color: #3b82f6; font-weight: 600; display: flex; align-items: center; gap: 4px;">
                        <span>🏢</span> Production Mode
                    </div>
                    <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">
                        DB: <code>simuguard_history.db</code> (Live)
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Sidebar Footer
        st.markdown(
            f"""
            <div class="sg-sidebar-footer">
                <div><strong>Engine:</strong> SimuGuard Core {APP_VERSION}</div>
                <div><strong>Persistence:</strong> Local SQLite</div>
                <div style="margin-top: 4px; color: #475569;">Environment: Air-gapped / Local</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        return st.session_state["active_page"]

        return st.session_state["active_page"]

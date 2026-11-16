"""Sidebar navigation component for SimuGuard AI dashboard."""

import streamlit as st
from config.settings import (
    APP_TITLE,
    APP_VERSION,
    NAV_PAGES,
    PAGE_OVERVIEW,
)

PAGE_ICONS = {
    "Overview": "📊",
    "New Change Request": "➕",
    "Assessment History": "📋",
    "Assessment Results": "🔍",
    "Remediation Center": "🛠️",
    "Before & After Comparison": "⚖️",
    "Digital Twin Explorer": "🌐",
    "Reports & Exports": "📄",
    "Settings / About": "⚙️",
}


def render_sidebar() -> str:
    """Render the dark navy sidebar and return the selected page key."""
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
            st.session_state["active_page"] = PAGE_OVERVIEW

        current_page = st.session_state["active_page"]
        if current_page not in NAV_PAGES:
            current_page = PAGE_OVERVIEW

        current_idx = NAV_PAGES.index(current_page)

        def _format_func(page_name: str) -> str:
            icon = PAGE_ICONS.get(page_name, "•")
            return f"{icon}  {page_name}"

        selected = st.radio(
            label="Navigation",
            options=NAV_PAGES,
            index=current_idx,
            format_func=_format_func,
            key="nav_radio_selection",
        )

        st.session_state["active_page"] = selected

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

    return selected

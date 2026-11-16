"""Sidebar navigation component for SimuGuard AI dashboard."""

import streamlit as st
from config.settings import (
    APP_TITLE,
    APP_VERSION,
    NAV_PAGES,
    PAGE_HISTORY,
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
        radio_idx = NAV_PAGES.index(current_page) if current_page in NAV_PAGES else NAV_PAGES.index(PAGE_HISTORY)

        def _format_func(page_name: str) -> str:
            icon = PAGE_ICONS.get(page_name, "•")
            return f"{icon}  {page_name}"

        selected = st.radio(
            label="Navigation",
            options=NAV_PAGES,
            index=radio_idx,
            format_func=_format_func,
            key="nav_radio_selection",
        )

        if current_page in NAV_PAGES:
            st.session_state["active_page"] = selected
        else:
            # If in a sub-view (like Record Detail), update active_page only if user picks a different page
            if selected != PAGE_HISTORY:
                st.session_state["active_page"] = selected

        # Environment Controls (Milestone G Demo Readiness)
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style="font-size:0.74rem; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:4px;">
                ITSM Database Mode
            </div>
            """,
            unsafe_allow_html=True,
        )
        current_env = st.session_state.get("environment_mode", "DEMO")
        env_choice = st.selectbox(
            "Environment Mode",
            options=["Demo Sandbox (Apex Global)", "Production (Empty ITSM)"],
            index=0 if current_env == "DEMO" else 1,
            label_visibility="collapsed",
            key="env_selector_sidebar",
        )
        new_env = "DEMO" if "Demo" in env_choice else "PRODUCTION"
        if new_env != current_env:
            st.session_state["environment_mode"] = new_env
            st.rerun()

        if current_env == "DEMO":
            st.markdown(
                """
                <div style="font-size: 0.72rem; color: #10b981; margin-bottom: 6px;">
                    ● Active DB: <code>simuguard_demo.db</code>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("🔄 Reset Demo Scenarios", use_container_width=True, key="btn_reset_demo_sidebar"):
                from ui.services.demo_service import DemoEnvironmentService
                DemoEnvironmentService.reset_demo_database()
                st.toast("✅ Demo environment reset with 5 certified scenarios!", icon="🛡️")
                st.rerun()
        else:
            st.markdown(
                """
                <div style="font-size: 0.72rem; color: #3b82f6; margin-bottom: 6px;">
                    ● Active DB: <code>simuguard_history.db</code> (Clean)
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Guided Tour Quick Toggle
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        st.checkbox(
            "Show Guided Demo Tour",
            value=st.session_state.get("show_guided_tour", True),
            key="show_guided_tour",
            help="Display step-by-step executive demo guidance cards across dashboard pages.",
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

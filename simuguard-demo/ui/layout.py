"""Layout and page container utilities for SimuGuard AI."""

import streamlit as st
from config.settings import APP_TITLE, PAGE_NEW_ASSESSMENT
from ui.theme import apply_theme


def init_page_layout() -> None:
    """Set Streamlit page configuration and apply enterprise CSS theme."""
    st.set_page_config(
        page_title=f"{APP_TITLE} | Enterprise Change Risk Interface",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    apply_theme()


def render_page_header(title: str, description: str, action_button: bool = False, button_label: str = "") -> None:
    """Render a consistent header for each dashboard view."""
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown(
            f"""
            <div class="sg-page-header">
                <h1 class="sg-page-title">{title}</h1>
                <div class="sg-page-description">{description}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        if action_button and button_label:
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            if st.button(button_label, use_container_width=True):
                st.session_state["active_page"] = PAGE_NEW_ASSESSMENT
                st.rerun()

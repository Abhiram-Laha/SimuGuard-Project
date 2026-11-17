"""SimuGuard AI — Local Dashboard & Enterprise Change Management Interface.

Phase 6: Foundation Shell and Enterprise Theme (Milestone B).
"""

from pathlib import Path
import sys

# Ensure package directory and repository root are in Python sys.path
BASE_DIR = Path(__file__).parent.resolve()
for path_str in [str(BASE_DIR), str(BASE_DIR.parent.resolve())]:
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

import streamlit as st
from storage.database import init_db
from storage.repository import ChangeRepository
from ui.components.sidebar import render_sidebar
from ui.layout import init_page_layout
from ui.navigation import route_page


def main() -> None:
    """Main application entry point."""
    from config.settings import PAGE_NEW_ASSESSMENT

    if "environment_mode" not in st.session_state:
        st.session_state["environment_mode"] = "DEMO"

    if "active_page" not in st.session_state:
        st.session_state["active_page"] = PAGE_NEW_ASSESSMENT

    from ui.services.demo_service import DemoEnvironmentService

    if st.session_state["environment_mode"] == "DEMO":
        DemoEnvironmentService.ensure_demo_initialized()
        repository = DemoEnvironmentService.get_demo_repository()
    else:
        init_db()
        repository = ChangeRepository()

    # 2. Configure page layout & CSS theme
    init_page_layout()

    # 3. Render sidebar navigation
    selected_page = render_sidebar()

    # 4. Route to selected view
    route_page(selected_page, repository)


if __name__ == "__main__":
    main()

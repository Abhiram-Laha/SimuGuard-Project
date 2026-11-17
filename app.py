"""SimuGuard AI — Unified Streamlit Entry Point.

Intelligent Pre-Deployment Change Risk Assessment for Enterprise Network Security
and Cloud Identity Operations.

Designed for robust execution on Streamlit Community Cloud (Linux)
and local environments (Windows/macOS/Linux).
"""

from pathlib import Path
import sys

# 1. Ensure project root and package directory are in sys.path
REPO_ROOT = Path(__file__).resolve().parent
PKG_DIR = (REPO_ROOT / "simuguard-demo").resolve()

for path_str in [str(PKG_DIR), str(REPO_ROOT)]:
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

import streamlit as st
from config.settings import PAGE_NEW_ASSESSMENT
from storage.database import init_db
from storage.repository import ChangeRepository
from ui.components.sidebar import render_sidebar
from ui.layout import init_page_layout
from ui.navigation import route_page
from ui.services.demo_service import DemoEnvironmentService


def main() -> None:
    """Main application entry point."""
    if "environment_mode" not in st.session_state:
        st.session_state["environment_mode"] = "DEMO"

    if "active_page" not in st.session_state:
        st.session_state["active_page"] = PAGE_NEW_ASSESSMENT

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

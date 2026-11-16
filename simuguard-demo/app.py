"""SimuGuard AI — Local Dashboard & Enterprise Change Management Interface.

Phase 6: Foundation Shell and Enterprise Theme (Milestone B).
"""

from pathlib import Path
import sys

# Ensure repository root is in Python sys.path
BASE_DIR = Path(__file__).parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
from storage.database import init_db
from storage.repository import ChangeRepository
from ui.components.sidebar import render_sidebar
from ui.layout import init_page_layout
from ui.navigation import route_page


def main() -> None:
    """Main application entry point."""
    # 1. Initialize persistent SQLite database
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

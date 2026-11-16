"""Configuration and environment settings for SimuGuard AI (Phase 6)."""

from pathlib import Path

# Repository and Data Paths
REPO_ROOT = Path(__file__).parent.parent.resolve()
DATA_DIR = REPO_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "simuguard_history.db"
DEMO_DB_PATH = DATA_DIR / "simuguard_demo.db"
UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

ARTIFACTS_DIR = DATA_DIR / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

DEMO_ENV_DIR = REPO_ROOT / "demo_environment"
CHANGES_DIR = REPO_ROOT / "changes"
DELIVERABLES_DIR = REPO_ROOT / "deliverables"
SCREENSHOTS_DIR = DELIVERABLES_DIR / "screenshots"

# Application Branding
APP_TITLE = "SimuGuard AI"
APP_SUBTITLE = "Intelligent Pre-Deployment Change Risk Assessment"
APP_VERSION = "0.6.0"
APP_DESCRIPTION = (
    "Local, deterministic change-risk simulation and automated remediation engine for "
    "enterprise Network Security and Identity Operations."
)

# Navigation Pages (Simplified Engineer Experience)
PAGE_NEW_ASSESSMENT = "New Assessment"
PAGE_HISTORY = "Assessment History"
PAGE_REPORTS = "Reports"
PAGE_SETTINGS = "Settings & Diagnostics"

NAV_PAGES = [
    PAGE_NEW_ASSESSMENT,
    PAGE_HISTORY,
    PAGE_REPORTS,
    PAGE_SETTINGS,
]

# Legacy Page Constants (Maintained for backward compatibility and sub-routes)
PAGE_OVERVIEW = "Overview"
PAGE_NEW_CHANGE = "New Change Request"
PAGE_RESULTS = "Assessment Results"
PAGE_REMEDIATION = "Remediation Center"
PAGE_COMPARISON = "Before & After Comparison"
PAGE_DIGITAL_TWIN = "Digital Twin Explorer"
PAGE_ABOUT = "Settings / About"
PAGE_REPORTS_EXPORTS = "Reports & Exports"

# Color Palette (ServiceNow-inspired dark sidebar, clean light workspace)
COLORS = {
    "sidebar_bg": "#0f172a",
    "sidebar_active": "#1e293b",
    "sidebar_text": "#f8fafc",
    "sidebar_muted": "#94a3b8",
    "main_bg": "#f8fafc",
    "card_bg": "#ffffff",
    "border": "#e2e8f0",
    "primary": "#0f62fe",
    "primary_hover": "#0043ce",
    "verdict_allow": "#10b981",
    "verdict_warn": "#f59e0b",
    "verdict_block": "#ef4444",
    "verdict_unknown": "#64748b",
}

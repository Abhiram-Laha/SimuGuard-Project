"""Custom CSS theme and styling rules for SimuGuard AI dashboard."""

import streamlit as st


ENTERPRISE_CSS = """
<style>
/* Global App Background & Typography */
.stApp {
    background-color: #f8fafc;
    color: #1e293b;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Sidebar Dark Navy Styling */
section[data-testid="stSidebar"] {
    background-color: #0f172a !important;
    border-right: 1px solid #1e293b;
}

section[data-testid="stSidebar"] div.stRadio > label {
    display: none;
}

section[data-testid="stSidebar"] div.stRadio > div[role="radiogroup"] > label {
    color: #94a3b8 !important;
    background-color: transparent !important;
    padding: 10px 14px;
    border-radius: 6px;
    margin-bottom: 3px;
    font-size: 0.92rem;
    font-weight: 500;
    transition: all 0.15s ease-in-out;
}

section[data-testid="stSidebar"] div.stRadio > div[role="radiogroup"] > label:hover {
    color: #f8fafc !important;
    background-color: #1e293b !important;
}

section[data-testid="stSidebar"] div.stRadio > div[role="radiogroup"] > label[data-checked="true"],
section[data-testid="stSidebar"] div.stRadio > div[role="radiogroup"] > label:has(input:checked) {
    color: #ffffff !important;
    background-color: #1e293b !important;
    border-left: 3px solid #0f62fe !important;
    font-weight: 600;
}

/* Sidebar Header & Footer */
.sg-sidebar-header {
    padding: 1rem 0.5rem 1.25rem 0.5rem;
    border-bottom: 1px solid #1e293b;
    margin-bottom: 1.25rem;
}

.sg-sidebar-title {
    color: #f8fafc;
    font-size: 1.25rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 8px;
}

.sg-sidebar-subtitle {
    color: #94a3b8;
    font-size: 0.78rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 4px;
}

.sg-sidebar-footer {
    padding: 1rem 0.5rem;
    border-top: 1px solid #1e293b;
    margin-top: 2rem;
    font-size: 0.75rem;
    color: #64748b;
}

/* Standard Content Cards */
.sg-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px 0 rgba(0, 0, 0, 0.02);
}

.sg-card-header {
    font-size: 1.05rem;
    font-weight: 600;
    color: #0f172a;
    margin-bottom: 0.75rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #f1f5f9;
    padding-bottom: 0.5rem;
}

/* Metric Display Cards */
.sg-metric-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 1.1rem 1.25rem;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
    height: 100%;
}

.sg-metric-label {
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #64748b;
    margin-bottom: 0.35rem;
}

.sg-metric-value {
    font-size: 1.85rem;
    font-weight: 700;
    color: #0f172a;
    line-height: 1.2;
}

.sg-metric-hint {
    font-size: 0.75rem;
    color: #94a3b8;
    margin-top: 0.35rem;
}

/* Status Badges & Pills */
.sg-badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-align: center;
    letter-spacing: 0.02em;
}

.sg-badge-allow {
    background-color: #ecfdf5;
    color: #065f46;
    border: 1px solid #a7f3d0;
}

.sg-badge-warn {
    background-color: #fffbeb;
    color: #92400e;
    border: 1px solid #fde68a;
}

.sg-badge-block {
    background-color: #fef2f2;
    color: #991b1b;
    border: 1px solid #fecaca;
}

.sg-badge-neutral {
    background-color: #f1f5f9;
    color: #475569;
    border: 1px solid #e2e8f0;
}

.sg-badge-info {
    background-color: #eff6ff;
    color: #1e40af;
    border: 1px solid #bfdbfe;
}

.sg-badge-purple {
    background-color: #faf5ff;
    color: #6b21a8;
    border: 1px solid #e9d5ff;
}

/* Priority Pills */
.sg-prio-emergency {
    background-color: #fef2f2;
    color: #b91c1c;
    border: 1px solid #fca5a5;
    font-weight: 700;
}

.sg-prio-expedited {
    background-color: #fff7ed;
    color: #c2410c;
    border: 1px solid #fdba74;
}

.sg-prio-normal {
    background-color: #f0fdf4;
    color: #15803d;
    border: 1px solid #bbf7d0;
}

.sg-prio-standard {
    background-color: #f8fafc;
    color: #475569;
    border: 1px solid #e2e8f0;
}

/* Buttons Styling */
.stButton > button {
    background-color: #0f62fe;
    color: #ffffff;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.9rem;
    border: none;
    padding: 0.5rem 1.25rem;
    transition: background-color 0.15s ease-in-out;
}

.stButton > button:hover {
    background-color: #0043ce;
    color: #ffffff;
}

/* Page Header */
.sg-page-header {
    margin-bottom: 1.5rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid #e2e8f0;
}

.sg-page-title {
    font-size: 1.6rem;
    font-weight: 700;
    color: #0f172a;
    margin: 0;
}

.sg-page-description {
    font-size: 0.9rem;
    color: #64748b;
    margin-top: 0.25rem;
}

/* Empty State Box */
.sg-empty-state {
    text-align: center;
    padding: 3rem 1.5rem;
    background-color: #ffffff;
    border: 1px dashed #cbd5e1;
    border-radius: 8px;
    color: #64748b;
}

.sg-empty-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #334155;
    margin-top: 0.75rem;
    margin-bottom: 0.5rem;
}

.sg-empty-subtitle {
    font-size: 0.88rem;
    color: #64748b;
    max-width: 480px;
    margin: 0 auto 1.25rem auto;
}

/* Primary Change Request Intake Text Area (Single Assessment Workspace) */
div.st-key-txt_servicenow_input textarea,
div[data-testid="stTextArea"]:has(textarea[aria-label*="ServiceNow Change Request Input"]) textarea {
    background-color: #0f172a !important;
    color: #f8fafc !important;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
    font-size: 0.88rem !important;
    line-height: 1.55 !important;
    border: 1px solid #334155 !important;
    border-radius: 6px !important;
    width: 100% !important;
    overflow-y: auto !important;
    resize: vertical !important;
}

div.st-key-txt_servicenow_input textarea:focus,
div[data-testid="stTextArea"]:has(textarea[aria-label*="ServiceNow Change Request Input"]) textarea:focus {
    border-color: #0f62fe !important;
    box-shadow: 0 0 0 2px rgba(15, 98, 254, 0.25) !important;
    outline: none !important;
}

div.st-key-txt_servicenow_input textarea::placeholder,
div[data-testid="stTextArea"]:has(textarea[aria-label*="ServiceNow Change Request Input"]) textarea::placeholder {
    color: #94a3b8 !important;
    opacity: 0.85;
}
</style>
"""


def apply_theme() -> None:
    """Inject enterprise styling rules into the active Streamlit app session."""
    st.markdown(ENTERPRISE_CSS, unsafe_allow_html=True)

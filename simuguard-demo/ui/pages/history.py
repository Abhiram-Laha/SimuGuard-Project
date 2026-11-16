"""Assessment History Page — searchable, filterable log of enterprise change requests."""

import math
from typing import Any, Dict, List, Optional
import streamlit as st

from config.settings import PAGE_NEW_CHANGE
from storage.repository import ChangeRepository
from ui.components.status_badges import (
    render_priority_badge,
    render_risk_score_badge,
    render_verdict_badge,
    render_workflow_badge,
)
from ui.layout import render_page_header


def render_history_page(repository: ChangeRepository) -> None:
    """Render the searchable and filterable Assessment History dashboard."""
    render_page_header(
        title="Change Assessment History",
        description="Audit log and historical repository of all submitted, analyzed, and remediated security change requests.",
        action_button=True,
        button_label="➕ New Change Request",
    )

    # 1. Search and Filter Bar
    with st.expander("🔍 Search & Filter Filters", expanded=True):
        col_f1, col_f2, col_f3, col_f4 = st.columns([2, 1, 1, 1])
        with col_f1:
            search_query = st.text_input(
                "Search Requests",
                placeholder="Search by Request #, title, or keywords...",
                key="history_search_query",
            )
        with col_f2:
            filter_domain = st.selectbox(
                "Domain",
                options=["ALL", "NETWORK_SECURITY", "IDENTITY_GOVERNANCE", "MULTI_DOMAIN"],
                index=0,
                key="history_filter_domain",
            )
        with col_f3:
            filter_priority = st.selectbox(
                "Priority",
                options=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "EMERGENCY", "EXPEDITED", "NORMAL", "STANDARD"],
                index=0,
                key="history_filter_priority",
            )
        with col_f4:
            filter_status = st.selectbox(
                "Workflow State",
                options=["ALL", "DRAFT", "SUBMITTED", "ANALYSIS_COMPLETE", "REMEDIATED", "VALIDATED", "APPROVED", "REJECTED"],
                index=0,
                key="history_filter_status",
            )

        col_sort1, col_sort2, col_sort3 = st.columns([1, 1, 2])
        with col_sort1:
            sort_order = st.selectbox(
                "Sort Order",
                options=["Newest First (DESC)", "Oldest First (ASC)"],
                index=0,
                key="history_sort_order",
            )
        with col_sort2:
            page_size = st.selectbox(
                "Records Per Page",
                options=[10, 25, 50],
                index=0,
                key="history_page_size",
            )
        with col_sort3:
            # Quick Reset Filters button
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("Reset All Filters"):
                st.session_state["history_search_query"] = ""
                st.session_state["history_filter_domain"] = "ALL"
                st.session_state["history_filter_priority"] = "ALL"
                st.session_state["history_filter_status"] = "ALL"
                st.rerun()

    # Determine pagination
    if "history_page_num" not in st.session_state:
        st.session_state["history_page_num"] = 1

    current_page = st.session_state["history_page_num"]
    safe_order = "ASC" if "Oldest" in sort_order else "DESC"

    total_records = repository.count_filtered_change_requests(
        search_query=search_query,
        domain=filter_domain,
        priority=filter_priority,
        status=filter_status,
    )

    total_pages = max(1, math.ceil(total_records / page_size))
    if current_page > total_pages:
        current_page = total_pages
        st.session_state["history_page_num"] = current_page

    offset = (current_page - 1) * page_size

    # Fetch records
    records = repository.filter_change_requests(
        search_query=search_query,
        domain=filter_domain,
        priority=filter_priority,
        status=filter_status,
        sort_field="created_at",
        sort_order=safe_order,
        limit=page_size,
        offset=offset,
    )

    # 2. Results Header
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin: 1.25rem 0 0.75rem 0;">
            <div style="font-size: 0.92rem; color: #475569; font-weight: 600;">
                Showing {len(records)} of {total_records} Change Requests (Page {current_page} of {total_pages})
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Render Table or Empty State
    if not records:
        st.markdown(
            """
            <div class="sg-empty-state">
                <div style="font-size: 2.2rem;">📋</div>
                <div class="sg-empty-title">No Matching Change Requests Found</div>
                <div class="sg-empty-subtitle">
                    No change requests matched your search or filter criteria.
                    Try resetting filters or submit a new change request.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        col_e1, col_e2, col_e3 = st.columns([1, 1, 1])
        with col_e2:
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            if st.button("➕ Submit New Change Request", key="btn_empty_new_change"):
                st.session_state["active_page"] = PAGE_NEW_CHANGE
                st.rerun()
        return

    # Render interactive record rows
    for r in records:
        req_no = r.get("request_number", "")
        title = r.get("title", "")
        domain = r.get("domain", "")
        prio = r.get("priority", "NORMAL")
        state = r.get("status", "SUBMITTED")
        created = r.get("created_at", "")[:19].replace("T", " ")
        verdict = r.get("verdict")
        score = r.get("composite_risk_score")
        requester = r.get("submitted_by", "SecOps Engineer")

        prio_badge = render_priority_badge(prio)
        state_badge = render_workflow_badge(state)
        verdict_badge = render_verdict_badge(verdict) if verdict else '<span class="sg-badge sg-badge-neutral">UNASSESSED</span>'
        score_badge = render_risk_score_badge(score) if score is not None else '<span style="color:#94a3b8;">-</span>'

        with st.container():
            st.markdown(
                f"""
                <div class="sg-card" style="padding: 1rem 1.25rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                        <div>
                            <span style="font-family: monospace; font-size: 1.05rem; font-weight: 700; color: #0f62fe;">
                                {req_no}
                            </span>
                            <span style="margin: 0 8px; color: #cbd5e1;">|</span>
                            <span style="font-size: 1rem; font-weight: 600; color: #0f172a;">
                                {title}
                            </span>
                        </div>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            {prio_badge}
                            {state_badge}
                            {verdict_badge}
                        </div>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem; color: #64748b;">
                        <div>
                            <span>Domain: <strong>{domain}</strong></span>
                            <span style="margin: 0 8px;">•</span>
                            <span>Requested By: <strong>{requester}</strong></span>
                            <span style="margin: 0 8px;">•</span>
                            <span>Created: <strong>{created} UTC</strong></span>
                        </div>
                        <div>
                            <span>Risk Score: {score_badge}</span>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            col_act1, col_act2 = st.columns([6, 1])
            with col_act2:
                if st.button("Inspect Record →", key=f"btn_view_{req_no}", use_container_width=True):
                    st.session_state["viewing_request_number"] = req_no
                    st.session_state["active_page"] = "Record Detail"
                    st.rerun()

    # Pagination Controls
    if total_pages > 1:
        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)
        col_p1, col_p2, col_p3 = st.columns([1, 2, 1])
        with col_p1:
            if current_page > 1:
                if st.button("← Previous Page"):
                    st.session_state["history_page_num"] = current_page - 1
                    st.rerun()
        with col_p2:
            st.markdown(
                f"<div style='text-align: center; color: #64748b; font-size: 0.88rem; padding-top: 6px;'>Page {current_page} of {total_pages}</div>",
                unsafe_allow_html=True,
            )
        with col_p3:
            if current_page < total_pages:
                if st.button("Next Page →"):
                    st.session_state["history_page_num"] = current_page + 1
                    st.rerun()

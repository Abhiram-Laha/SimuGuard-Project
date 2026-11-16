"""Reusable status badge and pill renderers."""

import html


def render_verdict_badge(verdict: str) -> str:
    """Return HTML string for deployment verdict badge."""
    v = (verdict or "").strip().upper()
    safe_v = html.escape(v)
    if v == "ALLOW":
        return f'<span class="sg-badge sg-badge-allow">● {safe_v}</span>'
    elif v == "WARN_MANUAL_REVIEW":
        return f'<span class="sg-badge sg-badge-warn">▲ {safe_v}</span>'
    elif v == "BLOCK_DEPLOYMENT":
        return f'<span class="sg-badge sg-badge-block">✕ {safe_v}</span>'
    else:
        return f'<span class="sg-badge sg-badge-neutral">{safe_v or "PENDING"}</span>'


def render_workflow_badge(status: str) -> str:
    """Return HTML string for ITSM change lifecycle status."""
    s = (status or "").strip().upper()
    safe_s = html.escape(s)
    if s in ("APPROVED", "VALIDATED", "CLOSED"):
        return f'<span class="sg-badge sg-badge-allow">{safe_s}</span>'
    elif s in ("ANALYSIS_COMPLETE", "REMEDIATED"):
        return f'<span class="sg-badge sg-badge-info">{safe_s}</span>'
    elif s in ("SUBMITTED", "DRAFT"):
        return f'<span class="sg-badge sg-badge-neutral">{safe_s}</span>'
    elif s in ("ANALYZING", "REMEDIATING"):
        return f'<span class="sg-badge sg-badge-purple">{safe_s}</span>'
    elif s in ("REJECTED",):
        return f'<span class="sg-badge sg-badge-block">{safe_s}</span>'
    else:
        return f'<span class="sg-badge sg-badge-neutral">{safe_s}</span>'


def render_priority_badge(priority: str) -> str:
    """Return HTML string for change priority."""
    p = (priority or "").strip().upper()
    safe_p = html.escape(p)
    if p == "EMERGENCY":
        return f'<span class="sg-badge sg-prio-emergency">{safe_p}</span>'
    elif p == "EXPEDITED":
        return f'<span class="sg-badge sg-prio-expedited">{safe_p}</span>'
    elif p == "NORMAL":
        return f'<span class="sg-badge sg-prio-normal">{safe_p}</span>'
    else:
        return f'<span class="sg-badge sg-prio-standard">{safe_p}</span>'


def render_risk_score_badge(score: float) -> str:
    """Return HTML string for composite risk score pill."""
    score_val = float(score) if score is not None else 0.0
    if score_val >= 70.0:
        cls = "sg-badge-block"
    elif score_val >= 30.0:
        cls = "sg-badge-warn"
    else:
        cls = "sg-badge-allow"
    return f'<span class="sg-badge {cls}">{score_val:.1f} / 100</span>'

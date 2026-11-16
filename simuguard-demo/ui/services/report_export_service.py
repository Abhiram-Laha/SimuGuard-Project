"""Report Export Service — builds executive PDF reports and structured JSON exports for Change Requests."""

from datetime import datetime, timezone
import html
import io
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from storage.models import AssessmentRecord, ChangeRequestRecord, RemediationRecord

# Styling Colors
NAVY = colors.HexColor("#0f172a")
DARK_SLATE = colors.HexColor("#1e293b")
TEXT_MUTED = colors.HexColor("#475569")
ACCENT_BLUE = colors.HexColor("#0f62fe")
BORDER_COLOR = colors.HexColor("#e2e8f0")
LIGHT_BG = colors.HexColor("#f8fafc")

VERDICT_GREEN = colors.HexColor("#10b981")
VERDICT_AMBER = colors.HexColor("#f59e0b")
VERDICT_RED = colors.HexColor("#ef4444")


class ReportNumberedCanvas(canvas.Canvas):
    """Two-pass canvas drawing running headers and footers with total page counts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)

        # Header (Pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 756, "SimuGuard AI — Executive Change Risk Assessment Report")
            self.drawRightString(576, 756, "Apex Global Technologies")
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)

        # Footer (All pages)
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(36, 45, 576, 45)
        self.drawString(36, 34, "SimuGuard AI Platform | Confidential & Pre-Deployment Audit Artifact")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 34, page_str)
        self.restoreState()


def get_safe_export_filename(
    request_number: str,
    assessment_id: Optional[str] = None,
    extension: str = "pdf",
) -> str:
    """Generate a clean, sanitized export filename."""
    req_clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", request_number)
    asmt_clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", assessment_id or "latest")
    ext_clean = extension.lstrip(".").lower()
    return f"SimuGuard_{req_clean}_{asmt_clean}.{ext_clean}"


def build_executive_json(
    request_record: ChangeRequestRecord,
    assessment_record: AssessmentRecord,
    remediation_record: Optional[RemediationRecord] = None,
) -> str:
    """Generate a structured, validated JSON export artifact."""
    raw_assessment = {}
    if assessment_record.raw_json:
        try:
            raw_assessment = json.loads(assessment_record.raw_json)
        except Exception:
            pass

    raw_plan = {}
    raw_comp = {}
    if remediation_record:
        if remediation_record.plan_json:
            try:
                raw_plan = json.loads(remediation_record.plan_json)
            except Exception:
                pass
        if remediation_record.comparison_json:
            try:
                raw_comp = json.loads(remediation_record.comparison_json)
            except Exception:
                pass

    metadata_payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "engine": "SimuGuard AI Enterprise Risk Core v0.6.0",
        "environment": "Apex Global Digital Twin (Simulated / Local)",
        "organization": "Apex Global Technologies",
        "classification": "CONFIDENTIAL - INTERNAL ITSM ARTIFACT",
    }

    assessment_payload = {
        "assessment_id": assessment_record.assessment_id,
        "timestamp": assessment_record.timestamp,
        "verdict": assessment_record.verdict,
        "composite_risk_score": assessment_record.composite_risk_score,
        "severity_counts": {
            "critical": assessment_record.critical_count,
            "high": assessment_record.high_count,
            "medium": assessment_record.medium_count,
            "low": assessment_record.low_count,
            "total": assessment_record.security_gaps_count,
        },
        "blast_radius_nodes_count": assessment_record.blast_radius_nodes_count,
        "executive_summary": raw_assessment.get("executive_summary", ""),
        "identified_security_gaps": raw_assessment.get("identified_security_gaps", []),
        "security_gaps": raw_assessment.get("identified_security_gaps", []),
        "predicted_affected_assets": raw_assessment.get("predicted_affected_assets", []),
        "pre_implementation_validation_plan": raw_assessment.get("pre_implementation_validation_plan", []),
    }

    export_payload = {
        "schema_version": "1.0.0",
        "export_metadata": metadata_payload,
        "audit_metadata": metadata_payload,
        "change_request": request_record.model_dump(),
        "change_ticket": request_record.model_dump(),
        "assessment": assessment_payload,
        "simulation_assessment": assessment_payload,
        "affected_infrastructure_assets": raw_assessment.get("predicted_affected_assets", []),
        "remediation_plan": {
            "plan_id": raw_plan.get("plan_id"),
            "plan_status": remediation_record.status if remediation_record else "NOT_GENERATED",
            "recommendations": raw_plan.get("recommendations", []),
            "synthesized_candidate_hcl": remediation_record.synthesized_hcl if remediation_record else None,
        },
        "remediation": {
            "plan_id": raw_plan.get("plan_id"),
            "plan_status": remediation_record.status if remediation_record else "NOT_GENERATED",
            "recommendations": raw_plan.get("recommendations", []),
            "synthesized_candidate_hcl": remediation_record.synthesized_hcl if remediation_record else None,
        },
        "differential_comparison": {
            "risk_score_before": raw_comp.get("risk_score_before", assessment_record.composite_risk_score),
            "risk_score_after": raw_comp.get("risk_score_after"),
            "risk_score_delta": raw_comp.get("risk_score_delta", 0),
            "verdict_before": raw_comp.get("verdict_before", assessment_record.verdict),
            "verdict_after": raw_comp.get("verdict_after"),
            "finding_resolutions": raw_comp.get("finding_resolutions", []),
            "resolved_count": raw_comp.get("resolved_count", 0),
            "manual_review_count": raw_comp.get("manual_review_count", 0),
        },
        "disclaimer": (
            "This report is generated by local deterministic graph simulation and policy analysis. "
            "Simulated verdicts and blast radii represent pre-flight risk projections and do not replace "
            "formal Change Advisory Board (CAB) review."
        ),
    }

    return json.dumps(export_payload, indent=2)


def build_executive_pdf(
    request_record: ChangeRequestRecord,
    assessment_record: AssessmentRecord,
    remediation_record: Optional[RemediationRecord] = None,
) -> bytes:
    """Generate a publication-grade executive PDF assessment report using ReportLab."""
    raw_assessment = {}
    if assessment_record.raw_json:
        try:
            raw_assessment = json.loads(assessment_record.raw_json)
        except Exception:
            pass

    raw_plan = {}
    raw_comp = {}
    if remediation_record:
        if remediation_record.plan_json:
            try:
                raw_plan = json.loads(remediation_record.plan_json)
            except Exception:
                pass
        if remediation_record.comparison_json:
            try:
                raw_comp = json.loads(remediation_record.comparison_json)
            except Exception:
                pass

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles with unique names
    title_style = ParagraphStyle(
        "ExecReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=NAVY,
    )
    subtitle_style = ParagraphStyle(
        "ExecReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=TEXT_MUTED,
    )
    h2_style = ParagraphStyle(
        "ExecReportH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=NAVY,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ExecReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=DARK_SLATE,
    )
    code_style = ParagraphStyle(
        "ExecReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=NAVY,
    )

    story = []

    # Title & Metadata Banner
    story.append(Paragraph("SimuGuard AI — Pre-Flight Security Change Risk Assessment", title_style))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"Apex Global Technologies • Domain: apex-global.example • Assessment ID: <b>{assessment_record.assessment_id}</b>",
            subtitle_style,
        )
    )
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT_BLUE, spaceAfter=12))

    # Verdict & Summary Banner
    verdict = assessment_record.verdict
    v_color = VERDICT_GREEN if verdict == "ALLOW" else (VERDICT_AMBER if verdict == "WARN_MANUAL_REVIEW" else VERDICT_RED)

    verdict_table_data = [
        [
            Paragraph(f"<b>GATE VERDICT</b><br/><font size='14' color='{v_color.hexval()}'><b>{verdict}</b></font>", body_style),
            Paragraph(f"<b>RISK SCORE</b><br/><font size='14'><b>{assessment_record.composite_risk_score:.1f} / 100</b></font>", body_style),
            Paragraph(f"<b>IDENTIFIED GAPS</b><br/><font size='14'><b>{assessment_record.security_gaps_count}</b></font>", body_style),
            Paragraph(f"<b>BLAST RADIUS</b><br/><font size='14'><b>{assessment_record.blast_radius_nodes_count} Assets</b></font>", body_style),
        ]
    ]
    vt = Table(verdict_table_data, colWidths=[135, 135, 135, 135])
    vt.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ])
    )
    story.append(vt)
    story.append(Spacer(1, 12))

    # Section 1: Change Request Details
    story.append(Paragraph("1. Change Request Information", h2_style))
    cr_data = [
        [Paragraph("<b>Request Number:</b>", body_style), Paragraph(html.escape(str(request_record.request_number)), code_style),
         Paragraph("<b>Priority:</b>", body_style), Paragraph(html.escape(str(request_record.priority)), body_style)],
        [Paragraph("<b>Short Description:</b>", body_style), Paragraph(html.escape(str(request_record.title)), body_style),
         Paragraph("<b>Change Type:</b>", body_style), Paragraph(html.escape(str(request_record.change_type)), body_style)],
        [Paragraph("<b>Domain:</b>", body_style), Paragraph(html.escape(str(request_record.domain)), body_style),
         Paragraph("<b>Assignment Group:</b>", body_style), Paragraph(html.escape(str(request_record.assignment_group)), body_style)],
        [Paragraph("<b>Requested By:</b>", body_style), Paragraph(html.escape(str(request_record.submitted_by)), body_style),
         Paragraph("<b>Planned Window:</b>", body_style), Paragraph(html.escape(str(request_record.maintenance_window)), body_style)],
    ]
    crt = Table(cr_data, colWidths=[100, 170, 100, 170])
    crt.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(crt)
    story.append(Spacer(1, 10))

    # Section 2: Executive Summary
    story.append(Paragraph("2. Executive Simulation Summary", h2_style))
    exec_summary = raw_assessment.get("executive_summary", "Simulation completed.")
    story.append(Paragraph(html.escape(str(exec_summary)), body_style))
    story.append(Spacer(1, 10))

    # Section 3: Security Findings
    story.append(Paragraph("3. Identified Security Gaps & Policy Violations", h2_style))
    gaps = raw_assessment.get("identified_security_gaps", [])
    if gaps:
        gap_rows = [[
            Paragraph("<b>Rule</b>", body_style),
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>Gap Title & Impact</b>", body_style),
            Paragraph("<b>Compliance & Guidance</b>", body_style),
        ]]
        for g in gaps:
            r_id = html.escape(str(g.get("rule_id", "GAP")))
            sev = html.escape(str(g.get("severity", "MEDIUM")))
            title = html.escape(str(g.get("gap_title", "")))
            impact = html.escape(str(g.get("technical_impact", "")))
            comp = html.escape(str(g.get("compliance_violation", "")))
            rem = html.escape(str(g.get("remediation_guidance", "")))
            gap_rows.append([
                Paragraph(f"<b>{r_id}</b>", code_style),
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(f"<b>{title}</b><br/>{impact}", body_style),
                Paragraph(f"<i>{comp}</i><br/><b>Fix:</b> {rem}", body_style),
            ])
        gt = Table(gap_rows, colWidths=[55, 60, 225, 200])
        gt.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(gt)
    else:
        story.append(Paragraph("No security gaps or policy violations identified.", body_style))

    story.append(Spacer(1, 12))

    # Section 4: Blast Radius Assets
    story.append(Paragraph("4. Blast Radius Traversal: Affected Assets", h2_style))
    assets = raw_assessment.get("predicted_affected_assets", [])
    if assets:
        asset_rows = [[
            Paragraph("<b>Asset ID</b>", body_style),
            Paragraph("<b>Display Name</b>", body_style),
            Paragraph("<b>Type</b>", body_style),
            Paragraph("<b>Tier</b>", body_style),
            Paragraph("<b>Criticality</b>", body_style),
        ]]
        for a in assets[:10]:
            asset_rows.append([
                Paragraph(html.escape(str(a.get("asset_id", ""))), code_style),
                Paragraph(html.escape(str(a.get("asset_name", ""))), body_style),
                Paragraph(html.escape(str(a.get("asset_type", ""))), body_style),
                Paragraph(html.escape(str(a.get("tier", "DIRECT"))), body_style),
                Paragraph(html.escape(str(a.get("criticality", "HIGH"))), body_style),
            ])
        at = Table(asset_rows, colWidths=[100, 140, 110, 80, 110])
        at.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("PADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(at)
    else:
        story.append(Paragraph("No direct sensitive assets impacted in blast radius.", body_style))

    story.append(Spacer(1, 12))

    # Section 5: Remediation & Differential Comparison
    story.append(Paragraph("5. Automated Remediation & Closed-Loop Validation", h2_style))
    if raw_comp:
        delta = raw_comp.get("risk_score_delta", 0)
        v_before = raw_comp.get("verdict_before", verdict)
        v_after = raw_comp.get("verdict_after", "ALLOW")
        res_cnt = raw_comp.get("resolved_count", 0)
        man_cnt = raw_comp.get("manual_review_count", 0)
        comp_text = (
            f"Candidate remediation pipeline synthesized an isolated patch. "
            f"Verdict transition: <b>{v_before}</b> ➔ <b>{v_after}</b>. "
            f"Risk score reduction: <b>-{delta} points</b>. "
            f"Verified <b>{res_cnt} resolved finding(s)</b> across Candidate Digital Twin overlay. "
            f"Residual manual reviews required: <b>{man_cnt}</b>."
        )
    else:
        comp_text = "No differential candidate validation record attached."
    story.append(Paragraph(comp_text, body_style))
    story.append(Spacer(1, 12))

    # Section 6: Limitations & Disclaimer
    story.append(Paragraph("6. Local Simulation Disclaimer", h2_style))
    disclaimer_text = (
        "This report is generated by SimuGuard AI local deterministic graph simulation and policy analysis. "
        "Evaluations are performed against the Apex Global synthetic Digital Twin without contacting live "
        "production firewalls or cloud APIs. Approval of this report does not supersede formal Change "
        "Advisory Board (CAB) authority."
    )
    story.append(Paragraph(disclaimer_text, body_style))

    # Build PDF
    doc.build(story, canvasmaker=ReportNumberedCanvas)
    buf.seek(0)
    return buf.getvalue()

"""Complete Enterprise Architecture PowerPoint Generator for Apex Global Technologies.

Generates: deliverables/Apex_Global_Technologies_Complete_Enterprise_Architecture.pptx
Reflects Phase 3.7 architecture: Palo Alto Networks, Panorama, AWS Multi-Account,
SailPoint Identity Security Cloud, 12 Business Applications, and 6 Data Assets.
"""

import sys
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# Paths
REPO_ROOT = Path(__file__).resolve().parent
DELIVERABLES_DIR = REPO_ROOT / "deliverables"
DELIVERABLES_DIR.mkdir(parents=True, exist_ok=True)
PPTX_PATH = DELIVERABLES_DIR / "Apex_Global_Technologies_Complete_Enterprise_Architecture.pptx"

# Initialize presentation (16:9 Widescreen)
prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

# Color Palette Constants
C_NAVY_DARK = RGBColor(11, 19, 43)     # #0B132B Dark Background
C_SLATE_DARK = RGBColor(28, 37, 65)    # #1C2541 Dark Card Fill
C_BG_LIGHT = RGBColor(248, 250, 252)   # #F8FAFC Light Background
C_CARD_BG = RGBColor(255, 255, 255)    # #FFFFFF White Card Fill
C_BORDER = RGBColor(203, 213, 225)     # #CBD5E1 Slate Border

C_TEXT_DARK = RGBColor(15, 23, 42)     # #0F172A Primary Dark Text
C_TEXT_MUTED = RGBColor(100, 116, 139) # #64748B Secondary Text
C_TEXT_WHITE = RGBColor(255, 255, 255)
C_TEXT_GOLD = RGBColor(245, 158, 11)   # #F59E0B Gold Accent

# Architectural Domain Colors
C_FIREWALL = RGBColor(220, 38, 38)     # #DC2626 Palo Alto Red
C_PANORAMA = RGBColor(124, 58, 237)    # #7C3AED Panorama Purple
C_AWS = RGBColor(2, 132, 199)          # #0284C7 AWS Cloud Blue
C_SAILPOINT = RGBColor(79, 70, 229)    # #4F46E5 SailPoint Indigo
C_WORKLOAD = RGBColor(5, 150, 105)     # #059669 Production Green
C_DATA = RGBColor(217, 119, 6)         # #D97706 Sensitive Data Amber
C_SECOPS = RGBColor(219, 39, 119)      # #DB2777 Security Pink
C_DEV = RGBColor(8, 145, 178)          # #0891B2 Development Cyan


# Helper Functions
def set_bg(slide, color):
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = color
    bg.line.fill.background()
    return bg


def add_header(slide, title, category, slide_num, is_dark=False):
    # Category tag
    tb_cat = slide.shapes.add_textbox(Inches(0.8), Inches(0.35), Inches(8.0), Inches(0.25))
    tf_cat = tb_cat.text_frame
    tf_cat.word_wrap = True
    tf_cat.margin_left = tf_cat.margin_top = tf_cat.margin_right = tf_cat.margin_bottom = 0
    p_cat = tf_cat.paragraphs[0]
    p_cat.text = category.upper()
    p_cat.font.size = Pt(8.5)
    p_cat.font.bold = True
    p_cat.font.name = "Arial"
    p_cat.font.color.rgb = C_TEXT_GOLD if is_dark else C_SAILPOINT

    # Title
    tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.58), Inches(10.5), Inches(0.55))
    tf_title = tb_title.text_frame
    tf_title.word_wrap = True
    tf_title.margin_left = tf_title.margin_top = tf_title.margin_right = tf_title.margin_bottom = 0
    p_title = tf_title.paragraphs[0]
    p_title.text = title
    p_title.font.size = Pt(19)
    p_title.font.bold = True
    p_title.font.name = "Arial"
    p_title.font.color.rgb = C_TEXT_WHITE if is_dark else C_TEXT_DARK

    # Slide number
    tb_num = slide.shapes.add_textbox(Inches(11.5), Inches(0.45), Inches(1.033), Inches(0.35))
    tf_num = tb_num.text_frame
    tf_num.word_wrap = True
    p_num = tf_num.paragraphs[0]
    p_num.alignment = PP_ALIGN.RIGHT
    p_num.text = f"{slide_num:02d} / 20"
    p_num.font.size = Pt(10)
    p_num.font.bold = True
    p_num.font.name = "Arial"
    p_num.font.color.rgb = C_TEXT_MUTED

    # Accent rule
    rule = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.18), Inches(11.733), Inches(0.015))
    rule.fill.solid()
    rule.fill.fore_color.rgb = RGBColor(51, 65, 85) if is_dark else RGBColor(226, 232, 240)
    rule.line.fill.background()


def add_card(slide, left, top, width, height, title="", subtitle="", bg_color=C_CARD_BG, border_color=C_BORDER, title_color=C_TEXT_DARK, title_size=11, sub_color=C_TEXT_MUTED, sub_size=8.5):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    card.line.color.rgb = border_color
    card.line.width = Pt(1.2)

    if title or subtitle:
        tb = slide.shapes.add_textbox(left + Inches(0.12), top + Inches(0.1), width - Inches(0.24), height - Inches(0.2))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        if title:
            p0 = tf.paragraphs[0]
            p0.text = title
            p0.font.bold = True
            p0.font.size = Pt(title_size)
            p0.font.name = "Arial"
            p0.font.color.rgb = title_color
        if subtitle:
            p1 = tf.add_paragraph()
            p1.text = subtitle
            p1.font.size = Pt(sub_size)
            p1.font.name = "Arial"
            p1.font.color.rgb = sub_color
            p1.space_before = Pt(2.5)
    return card


def add_pill(slide, left, top, width, height, text, bg_color, text_color=C_TEXT_WHITE, font_size=8):
    pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    pill.fill.solid()
    pill.fill.fore_color.rgb = bg_color
    pill.line.fill.background()
    tf = pill.text_frame
    tf.word_wrap = False
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.text = text
    p.alignment = PP_ALIGN.CENTER
    p.font.size = Pt(font_size)
    p.font.bold = True
    p.font.name = "Arial"
    p.font.color.rgb = text_color
    return pill


def add_stat_box(slide, left, top, width, height, number_str, label_str, accent_color):
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    box.fill.solid()
    box.fill.fore_color.rgb = C_CARD_BG
    box.line.color.rgb = accent_color
    box.line.width = Pt(1.5)

    tb = slide.shapes.add_textbox(left, top + Inches(0.08), width, height - Inches(0.16))
    tf = tb.text_frame
    tf.word_wrap = True
    p0 = tf.paragraphs[0]
    p0.alignment = PP_ALIGN.CENTER
    p0.text = number_str
    p0.font.bold = True
    p0.font.size = Pt(20)
    p0.font.name = "Arial"
    p0.font.color.rgb = accent_color

    p1 = tf.add_paragraph()
    p1.alignment = PP_ALIGN.CENTER
    p1.text = label_str
    p1.font.size = Pt(8)
    p1.font.bold = True
    p1.font.name = "Arial"
    p1.font.color.rgb = C_TEXT_DARK
    p1.space_before = Pt(2)
    return box


def add_table_grid(slide, left, top, width, height, headers, rows, col_widths, header_bg=C_NAVY_DARK):
    num_rows = len(rows) + 1
    num_cols = len(headers)
    table_shape = slide.shapes.add_table(num_rows, num_cols, left, top, width, height)
    table = table_shape.table

    for i, w in enumerate(col_widths):
        table.columns[i].width = w

    for c_idx, h in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = header_bg
        cell.text = h
        p = cell.text_frame.paragraphs[0]
        p.font.bold = True
        p.font.size = Pt(8.5)
        p.font.name = "Arial"
        p.font.color.rgb = C_TEXT_WHITE
        p.alignment = PP_ALIGN.CENTER

    for r_idx, row in enumerate(rows):
        is_even = r_idx % 2 == 0
        row_bg = C_CARD_BG if is_even else RGBColor(241, 245, 249)
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = row_bg
            cell.text = str(val)
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(7.5)
            p.font.name = "Arial"
            p.font.color.rgb = C_TEXT_DARK
            if c_idx == 0:
                p.font.bold = True
    return table_shape


# ==============================================================================
# SLIDE BUILDERS (1 TO 20)
# ==============================================================================

# --- SLIDE 1: Cover Page (Dark Theme) ---
def build_slide_01():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_NAVY_DARK)

    # Accent top bar
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(0.8), Inches(2.2), Inches(0.06))
    bar.fill.solid()
    bar.fill.fore_color.rgb = C_TEXT_GOLD
    bar.line.fill.background()

    # Pill badge
    add_pill(slide, Inches(0.8), Inches(1.1), Inches(4.5), Inches(0.35), "ENTERPRISE ARCHITECTURE SPECIFICATION | PHASE 3.7", C_SLATE_DARK, C_TEXT_GOLD, font_size=8.5)

    # Main Title
    tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(1.7), Inches(11.5), Inches(1.2))
    tf_title = tb_title.text_frame
    tf_title.word_wrap = True
    p0 = tf_title.paragraphs[0]
    p0.text = "Apex Global Technologies"
    p0.font.bold = True
    p0.font.size = Pt(36)
    p0.font.name = "Arial"
    p0.font.color.rgb = C_TEXT_WHITE

    p1 = tf_title.add_paragraph()
    p1.text = "Complete Enterprise Architecture & Identity Governance"
    p1.font.bold = True
    p1.font.size = Pt(22)
    p1.font.name = "Arial"
    p1.font.color.rgb = RGBColor(148, 163, 184)
    p1.space_before = Pt(6)

    # Subtitle / Scope
    tb_sub = slide.shapes.add_textbox(Inches(0.8), Inches(3.2), Inches(11.5), Inches(1.0))
    tf_sub = tb_sub.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = (
        "Comprehensive architectural blueprint covering Palo Alto Networks PAN-OS 11.1 Nebula firewalls, "
        "Panorama central management, AWS multi-account infrastructure, SailPoint Identity Security Cloud (ISC), "
        "12 enterprise business applications, 6 classified data repositories, and SimuGuard AI pre-deployment simulation."
    )
    p_sub.font.size = Pt(12)
    p_sub.font.name = "Arial"
    p_sub.font.color.rgb = RGBColor(203, 213, 225)

    # 4 Metadata Cards at Bottom
    card_w = Inches(2.75)
    card_gap = Inches(0.24)
    y_cards = Inches(4.7)

    metas = [
        ("ORGANISATION", "Apex Global Technologies Inc.\nDomain: apex-global.example\nGlobal Financial Technology", C_SAILPOINT),
        ("ARCHITECTURE STATE", "Phase 3.7 SailPoint Migration\nDecoupled Identity Governance\nRetained AWS Infrastructure", C_FIREWALL),
        ("SECURITY MODEL", "Defense-in-Depth Layered Control\n9 Network Security Zones\nZero-Trust Microsegmentation", C_WORKLOAD),
        ("SIMULATION TWIN", "SimuGuard AI Digital Twin\n220 Validated Assets / 77 Edges\nPre-Flight Change Verification", C_TEXT_GOLD),
    ]

    for idx, (m_title, m_desc, m_color) in enumerate(metas):
        x = Inches(0.8) + idx * (card_w + card_gap)
        c = add_card(slide, x, y_cards, card_w, Inches(1.8), title=m_title, subtitle=m_desc, bg_color=C_SLATE_DARK, border_color=m_color, title_color=m_color, title_size=10, sub_color=RGBColor(226, 232, 240), sub_size=8.5)

    # Footer note
    tb_foot = slide.shapes.add_textbox(Inches(0.8), Inches(6.8), Inches(11.733), Inches(0.3))
    tf_foot = tb_foot.text_frame
    p_f = tf_foot.paragraphs[0]
    p_f.text = "CONFIDENTIAL & PROPRIETARY — SYNTHETIC BENCHMARK SPECIFICATION FOR SIMUGUARD AI PRE-DEPLOYMENT SIMULATION"
    p_f.font.size = Pt(7.5)
    p_f.font.color.rgb = RGBColor(100, 116, 139)


# --- SLIDE 2: Executive Summary (Dark Theme) ---
def build_slide_02():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_NAVY_DARK)
    add_header(slide, "Strategic Architecture & Governance Overview", "Executive Summary", 2, is_dark=True)

    # 3 Strategy Cards
    w = Inches(3.75)
    h = Inches(3.4)
    y = Inches(1.4)
    gap = Inches(0.24)

    pillars = [
        (
            "Dual-Tier Firewall Defense",
            "Palo Alto PAN-OS 11.1 & Panorama",
            "• PA-5450 Internet Edge HA Pair enforces Layer 7 App-ID, Threat Prevention (Strict-Enterprise-Security), Inbound DNAT and Outbound PAT.\n"
            "• PA-3440 Internal Segmentation HA Pair isolates production microservices, developer sandboxes, databases, PCI DSS enclave, and CUI data vaults.\n"
            "• Panorama M-600 Virtual (pan-mgmt-01) manages shared device groups, template stacks, and multi-firewall commit pipelines.",
            C_FIREWALL,
        ),
        (
            "Decoupled Identity Governance",
            "SailPoint Identity Security Cloud",
            "• Authoritative governance plane (sp-tenant-apexglobal-01) manages 4 identity profiles, 22 identities, and 65 correlated accounts across 8 sources.\n"
            "• Three-tier RBAC hierarchy: 9 Roles -> 11 Access Profiles -> 13 Entitlements.\n"
            "• Rigorous lifecycle governance rules: PENDING_IS_NOT_ACCESS and PROVISIONING_GATE ensure unprovisioned requests convey ZERO effective runtime permissions.",
            C_SAILPOINT,
        ),
        (
            "Multi-Account Cloud & Data Vaults",
            "AWS Organization & 6 Data Repositories",
            "• AWS Organization (o-apexglobal01) with 3 dedicated accounts: Production (111122223333), Development (222233334444), and Security (333344445555).\n"
            "• 12 containerized applications hosted across EKS Kubernetes clusters and load balancers.\n"
            "• 6 classified data repositories protected by customer-managed KMS keys (NIST SP 800-171 CUI, PCI DSS token vault, Customer PII).",
            C_AWS,
        ),
    ]

    for idx, (p_title, p_sub, p_body, p_color) in enumerate(pillars):
        x = Inches(0.8) + idx * (w + gap)
        c = add_card(slide, x, y, w, h, title=p_title, subtitle=f"{p_sub}\n\n{p_body}", bg_color=C_SLATE_DARK, border_color=p_color, title_color=p_color, title_size=12, sub_color=RGBColor(226, 232, 240), sub_size=8.5)

    # 6 KPI Stat Boxes at Bottom
    y_stats = Inches(5.1)
    stat_w = Inches(1.8)
    stat_gap = Inches(0.186)
    stats = [
        ("4", "NGFW FIREWALLS\n(2 HA Pairs)", C_FIREWALL),
        ("9", "SECURITY ZONES\n(Zero-Trust)", C_PANORAMA),
        ("3", "AWS ACCOUNTS\n(Prod/Dev/Sec)", C_AWS),
        ("8", "GOVERNED SOURCES\n(SailPoint ISC)", C_SAILPOINT),
        ("12", "BUSINESS APPS\n(Tier 1/2/3)", C_WORKLOAD),
        ("6", "CLASSIFIED DATA\n(CUI & PCI Vaults)", C_DATA),
    ]

    for idx, (num, lbl, col) in enumerate(stats):
        x = Inches(0.8) + idx * (stat_w + stat_gap)
        add_stat_box(slide, x, y_stats, stat_w, Inches(1.6), num, lbl, col)


# --- SLIDE 3: Enterprise Technology Overview (Light Theme) ---
def build_slide_03():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Enterprise Technology Stack Across 5 Architecture Layers", "Technology Overview", 3)

    col_w = Inches(2.23)
    col_gap = Inches(0.14)
    y_cols = Inches(1.4)
    col_h = Inches(4.3)

    cols = [
        (
            "1. Perimeter Network",
            "Palo Alto PA-5450 HA",
            C_FIREWALL,
            [
                ("Platform", "PA-5450 HA Active/Passive"),
                ("OS", "PAN-OS 11.1 Nebula"),
                ("Zones", "Untrust, DMZ, Corp, Transit"),
                ("Ingress NAT", "Public IP -> ALB 10.100.4.15"),
                ("Egress NAT", "10.100.0.0/16 Outbound PAT"),
                ("Security Profiles", "Strict-Enterprise-Security"),
                ("VPN Access", "GlobalProtect Remote Access"),
            ],
        ),
        (
            "2. Segmentation",
            "Palo Alto PA-3440 HA",
            C_PANORAMA,
            [
                ("Platform", "PA-3440 HA Active/Passive"),
                ("OS", "PAN-OS 11.1 Nebula"),
                ("Interconnect", "10.255.0.0/30 Transit Route"),
                ("Zones", "Prod-App, Dev, DB, PCI, Vault"),
                ("Enforcement", "Zero-Trust Zone Policies"),
                ("App-ID Rules", "SQL, HTTPS, EKS Control"),
                ("Management", "Panorama (pan-mgmt-01)"),
            ],
        ),
        (
            "3. Cloud Infrastructure",
            "AWS Multi-Account",
            C_AWS,
            [
                ("AWS Org", "o-apexglobal01 (3 OUs)"),
                ("Prod (111122223333)", "vpc-prod-us-east-1 (10.100/16)"),
                ("Dev (222233334444)", "vpc-dev-us-east-1 (10.200/16)"),
                ("Sec (333344445555)", "vpc-sec-us-east-1 (10.250/16)"),
                ("Workloads", "4 EKS Clusters, 1 EC2 Forwarder"),
                ("Databases", "2 RDS PostgreSQL Clusters"),
                ("Key Management", "3 KMS Customer Managed Keys"),
            ],
        ),
        (
            "4. Identity Governance",
            "SailPoint ISC (Cloud)",
            C_SAILPOINT,
            [
                ("Tenant", "sp-tenant-apexglobal-01"),
                ("Domain", "apexglobal.identitynow.example"),
                ("Connected Sources", "8 Target Endpoints"),
                ("Identities", "22 Authoritative Identities"),
                ("Accounts", "65 Correlated User Accounts"),
                ("RBAC Framework", "9 Roles -> 11 APs -> 13 Ents"),
                ("Lifecycles", "Approvals & Certifications"),
            ],
        ),
        (
            "5. Applications & Data",
            "12 Apps & 6 Repositories",
            C_DATA,
            [
                ("Core Apps", "APP-001 Customer Web Portal"),
                ("PCI Engine", "APP-002 PCI Payment Processing"),
                ("Analytics", "APP-003 Customer Analytics"),
                ("Dependencies", "8 Cross-App API Call Paths"),
                ("Data Tier 1", "DATA-01 CUI Financial Vault"),
                ("Data Tier 2", "DATA-02 PCI Token Vault"),
                ("Compliance", "NIST 800-171, PCI DSS, SOX"),
            ],
        ),
    ]

    for idx, (c_title, c_sub, c_color, items) in enumerate(cols):
        x = Inches(0.8) + idx * (col_w + col_gap)
        c = add_card(slide, x, y_cols, col_w, col_h, title=c_title, subtitle=c_sub, bg_color=C_CARD_BG, border_color=c_color, title_color=c_color, title_size=10.5, sub_color=C_TEXT_DARK, sub_size=8.5)
        # Add item details inside card
        tb_items = slide.shapes.add_textbox(x + Inches(0.1), y_cols + Inches(0.7), col_w - Inches(0.2), col_h - Inches(0.8))
        tf = tb_items.text_frame
        tf.word_wrap = True
        for k, v in items:
            p = tf.add_paragraph()
            p.text = f"• {k}: {v}"
            p.font.size = Pt(7.5)
            p.font.name = "Arial"
            p.font.color.rgb = C_TEXT_DARK
            p.space_before = Pt(2)

    # Bottom Guiding Architecture Principles Banner
    add_card(
        slide,
        Inches(0.8),
        Inches(5.9),
        Inches(11.733),
        Inches(1.0),
        title="CORE ARCHITECTURAL DESIGN PRINCIPLES",
        subtitle=(
            "1. Separation of Governance & Enforcement: SailPoint governs access rights; AWS IAM & PAN-OS enforce runtime packet & API authorization.\n"
            "2. Zero-Trust Network Micro-Segmentation: Default Deny between all 9 security zones; multi-hop inspection required for sensitive tiers.\n"
            "3. Least Privilege & Enclave Protection: PCI Cardholder data and NIST SP 800-171 CUI financial records reside in dedicated isolated enclaves."
        ),
        bg_color=RGBColor(241, 245, 249),
        border_color=C_SAILPOINT,
        title_color=C_SAILPOINT,
        title_size=9,
        sub_color=C_TEXT_DARK,
        sub_size=7.5,
    )


# --- SLIDE 4: Complete Enterprise Architecture (Overall Architecture Diagram) ---
def build_slide_04():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "End-to-End Enterprise Architecture Topology", "Complete Architecture Diagram", 4)

    # Visual Multi-Tier Editable Architecture Layout
    y_start = Inches(1.35)

    # 1. External Ingress Row
    add_card(slide, Inches(0.8), y_start, Inches(3.6), Inches(0.7), title="Public Internet Ingress", subtitle="Untrusted Web Users (198.51.100.1)", bg_color=C_CARD_BG, border_color=C_FIREWALL, title_color=C_FIREWALL, title_size=9.5)
    add_card(slide, Inches(4.7), y_start, Inches(3.6), Inches(0.7), title="Corporate Remote Users", subtitle="GlobalProtect SSL/IPSec VPN Users", bg_color=C_CARD_BG, border_color=C_FIREWALL, title_color=C_FIREWALL, title_size=9.5)
    add_card(slide, Inches(8.6), y_start, Inches(3.933), Inches(0.7), title="Panorama Central Management", subtitle="pan-mgmt-01 (10.254.1.10) | OOB-Mgmt", bg_color=C_CARD_BG, border_color=C_PANORAMA, title_color=C_PANORAMA, title_size=9.5)

    # 2. Perimeter Layer
    y_perim = Inches(2.2)
    add_card(slide, Inches(0.8), y_perim, Inches(7.5), Inches(0.9), title="Internet Perimeter Firewall HA Pair: PA-5450 (PAN-OS 11.1 Nebula)", subtitle="Active: fw-edge-01-primary | Passive: fw-edge-02-secondary (HA1 Control / HA2 Data State Sync)\nEnforced Zones: Untrust-Internet, Trust-DMZ, Corp-Users, Transit-Internal | VR: vr-default-edge", bg_color=C_CARD_BG, border_color=C_FIREWALL, title_color=C_FIREWALL, title_size=10, sub_size=8)
    add_card(slide, Inches(8.6), y_perim, Inches(3.933), Inches(0.9), title="Device Groups & Templates", subtitle="DG-Internet-Perimeter & DG-Internal-Segmentation\nTemplate Stacks: Global-Baseline + Edge/Internal", bg_color=RGBColor(245, 243, 255), border_color=C_PANORAMA, title_color=C_PANORAMA, title_size=9.5, sub_size=8)

    # 3. Perimeter Zones Row
    y_zones1 = Inches(3.25)
    add_card(slide, Inches(0.8), y_zones1, Inches(3.6), Inches(0.75), title="Zone: Trust-DMZ (10.100.4.0/24)", subtitle="ALB Ingress (10.100.4.15) & Analytics Workers", bg_color=C_CARD_BG, border_color=C_WORKLOAD, title_size=9)
    add_card(slide, Inches(4.7), y_zones1, Inches(3.6), Inches(0.75), title="Zone: Corp-Users (10.10.0.0/16)", subtitle="Workstations, Laptops & On-Premises Users", bg_color=C_CARD_BG, border_color=C_BORDER, title_size=9)
    add_card(slide, Inches(8.6), y_zones1, Inches(3.933), Inches(0.75), title="Zone: Transit-Internal (10.255.0.0/30)", subtitle="Point-to-Point Interconnect: 10.255.0.1 <-> 10.255.0.2", bg_color=RGBColor(254, 243, 199), border_color=C_DATA, title_color=C_DATA, title_size=9)

    # 4. Internal Firewall Layer
    y_core = Inches(4.15)
    add_card(slide, Inches(0.8), y_core, Inches(11.733), Inches(0.85), title="Internal Segmentation Firewall HA Pair: PA-3440 (PAN-OS 11.1 Nebula)", subtitle="Active: fw-internal-01-primary | Passive: fw-internal-02-secondary (HA1 Control / HA2 Data Sync)\nEnforced Zones: Prod-App-Workloads, Dev-App-Workloads, Database-Backend, PCI-Cardholder-Data, Restricted-Data-Vault | VR: vr-internal-core", bg_color=C_CARD_BG, border_color=C_FIREWALL, title_color=C_FIREWALL, title_size=10, sub_size=8)

    # 5. Internal Zones & AWS Accounts
    y_aws = Inches(5.15)
    w_aws = Inches(3.75)
    add_card(
        slide,
        Inches(0.8),
        y_aws,
        w_aws,
        Inches(1.85),
        title="AWS Production (111122223333)",
        subtitle=(
            "VPC: vpc-prod-us-east-1 (10.100.0.0/16)\n"
            "• eks-customer-portal-cluster (Portal/Gateway)\n"
            "• eks-analytics-worker-pool (Analytics)\n"
            "• eks-payment-processor-pool (PCI Tokenizer)\n"
            "• rds-postgres-core-prod & rds-pci-token-vault\n"
            "• s3-enterprise-cui-vault (CUI Financial Vault)"
        ),
        bg_color=C_CARD_BG,
        border_color=C_AWS,
        title_color=C_AWS,
        title_size=10,
        sub_size=7.5,
    )

    add_card(
        slide,
        Inches(4.7),
        y_aws,
        w_aws,
        Inches(1.85),
        title="AWS Development & Security",
        subtitle=(
            "Dev Account (222233334444):\n"
            "• vpc-dev-us-east-1 (10.200.0.0/16)\n"
            "• eks-dev-cluster (Sandbox Microservices)\n"
            "• s3-dev-staging-telemetry (Telemetry Bucket)\n\n"
            "Security Account (333344445555):\n"
            "• vpc-sec-us-east-1 (10.250.0.0/16)\n"
            "• ec2-sec-siem-forwarder & s3-central-security-cloudtrail-sec"
        ),
        bg_color=C_CARD_BG,
        border_color=C_DEV,
        title_color=C_DEV,
        title_size=10,
        sub_size=7.5,
    )

    add_card(
        slide,
        Inches(8.6),
        y_aws,
        Inches(3.933),
        Inches(1.85),
        title="SailPoint ISC Governance Plane",
        subtitle=(
            "Tenant: sp-tenant-apexglobal-01 (ISC Cloud)\n"
            "• 8 Connected Target Sources (AWS, AD, Entra, Pan)\n"
            "• 4 ID Profiles, 22 Identities, 65 Accounts\n"
            "• 9 Roles -> 11 Access Profiles -> 13 Entitlements\n"
            "• Governs Access: GOVERNED_BY_SAILPOINT\n"
            "• Enforcement: Left to AWS IAM & PAN-OS"
        ),
        bg_color=RGBColor(238, 242, 255),
        border_color=C_SAILPOINT,
        title_color=C_SAILPOINT,
        title_size=10,
        sub_size=7.5,
    )


# --- SLIDE 5: Enterprise Network Topology & Routing (Light Theme) ---
def build_slide_05():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "HA Firewall Pairs, Virtual Routing & Subnet Segmentation", "Network Topology", 5)

    # Left Panel: HA & Routing Architecture
    add_card(
        slide,
        Inches(0.8),
        Inches(1.35),
        Inches(4.6),
        Inches(5.6),
        title="HIGH AVAILABILITY & VIRTUAL ROUTING",
        subtitle=(
            "Internet Perimeter Firewall Architecture:\n"
            "• Hardware: PA-5450 Dual-Chassis HA Pair in Active/Passive mode.\n"
            "• Primary Node: fw-edge-01-primary (enforces traffic actively).\n"
            "• Standby Node: fw-edge-02-secondary (hot standby with session sync).\n"
            "• HA1 Link: Dedicated 10 Gbps control link for heartbeats & config sync.\n"
            "• HA2 Link: Dedicated 10 Gbps data link for active session table replication.\n"
            "• Virtual Router: vr-default-edge routes between Untrust, DMZ, Corp & Transit.\n\n"
            "Internal Segmentation Firewall Architecture:\n"
            "• Hardware: PA-3440 Dual-Appliance HA Pair in Active/Passive mode.\n"
            "• Primary Node: fw-internal-01-primary (Active).\n"
            "• Standby Node: fw-internal-02-secondary (Passive).\n"
            "• HA1 / HA2: Dedicated links mirroring edge session synchronization.\n"
            "• Virtual Router: vr-internal-core enforces inter-zone micro-segmentation.\n\n"
            "Inter-Firewall Transit Interconnect:\n"
            "• Point-to-Point Transit Subnet: subnet-transit-interconnect (10.255.0.0/30).\n"
            "• Edge Interface: ethernet1/4 (10.255.0.1/30).\n"
            "• Internal Interface: ethernet1/1 (10.255.0.2/30).\n"
            "• Static Default Route: 0.0.0.0/0 on vr-internal-core points to 10.255.0.1."
        ),
        bg_color=C_CARD_BG,
        border_color=C_FIREWALL,
        title_color=C_FIREWALL,
        title_size=10.5,
        sub_size=7.5,
    )

    # Right Panel: 9 Subnets Table
    subnets_headers = ["Subnet ID", "CIDR Block", "VLAN", "Zone", "Allocated Workloads / Function"]
    subnets_rows = [
        ["subnet-prod-dmz-01", "10.100.4.0/24", "104", "Trust-DMZ", "ALB Ingress (10.100.4.15) & Analytics Pods"],
        ["subnet-corp-campus-01", "10.10.0.0/16", "10", "Corp-Users", "Campus Workstations & GlobalProtect VPN"],
        ["subnet-prod-app-01", "10.100.10.0/23", "110", "Prod-App", "Customer Web Portal & Order Settlement Pods"],
        ["subnet-dev-app-01", "10.200.10.0/23", "210", "Dev-App", "Ephemeral Developer Sandbox Pods"],
        ["subnet-prod-db-01", "10.100.20.0/24", "120", "Database", "Core Relational PostgreSQL Database Cluster"],
        ["subnet-prod-pci-01", "10.100.30.0/24", "130", "PCI-Cardholder", "Isolated PCI Tokenization Vault (Req 1.2)"],
        ["subnet-prod-vault-01", "10.100.40.0/24", "140", "Restricted-Vault", "NIST SP 800-171 CUI Financial S3 Endpoints"],
        ["subnet-mgmt-oob-01", "10.254.1.0/24", "254", "Mgmt-OOB", "Panorama (10.254.1.10) & Firewall Mgmt"],
        ["subnet-transit-interconnect", "10.255.0.0/30", "255", "Transit-Internal", "Point-to-Point Inter-Firewall Backbone"],
    ]
    col_w = [Inches(1.8), Inches(1.2), Inches(0.6), Inches(1.3), Inches(2.033)]
    add_table_grid(slide, Inches(5.6), Inches(1.35), Inches(6.933), Inches(5.6), subnets_headers, subnets_rows, col_w, header_bg=C_NAVY_DARK)


# --- SLIDE 6: Palo Alto Firewall Architecture & Policy Engine (Light Theme) ---
def build_slide_06():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "PAN-OS 11.1 Nebula Inspection, Threat Prevention & NAT", "Firewall Architecture", 6)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "Layer 7 Inspection Engines",
            "PAN-OS 11.1 Security Capabilities",
            C_FIREWALL,
            "• App-ID Protocol Classification:\n"
            "  Identifies actual application payloads regardless of port or SSL encryption (e.g., distinguishing web-browsing from SSH tunneling on port 443).\n\n"
            "• Threat Prevention Profile (Strict-Enterprise-Security):\n"
            "  - Anti-Spyware: Blocks C2 beaconing & DNS covert channels.\n"
            "  - Intrusion Prevention (IPS): Real-time vulnerability shielding.\n"
            "  - Anti-Virus: Inline deep packet malware inspection.\n"
            "  - WildFire: Automated zero-day sandbox detonation in cloud.\n\n"
            "• URL Filtering & Decryption:\n"
            "  SSL Forward Proxy inspection for enterprise workstations and outbound category-based web filtering.",
        ),
        (
            "Rulebase Architecture",
            "Pre-Rulebase, Local & Post-Rulebase",
            C_PANORAMA,
            "• Pre-Rulebase (Panorama Enforced):\n"
            "  Mandatory enterprise compliance rules pushed globally.\n"
            "  - Drop Inbound IP Spoofing (RFC 1918 on Untrust).\n"
            "  - Corporate DNS & NTP baseline authorization.\n"
            "  - Strict SQL port filtering to Database-Backend.\n\n"
            "• Device Group Rulebase (22 Rules Across Estate):\n"
            "  - DG-Internet-Perimeter: Ingress web-portal allow, VPN allow.\n"
            "  - DG-Internal-Segmentation: Production microservices to DB allow, strictly isolated PCI cardholder rule.\n\n"
            "• Post-Rulebase & Default Deny:\n"
            "  - Default interzone-default (Action: Deny, Log at Session End).\n"
            "  - Default intrazone-default (Action: Deny, Zero Trust).",
        ),
        (
            "NAT & Translation Architecture",
            "Inbound DNAT & Outbound PAT",
            C_AWS,
            "• Inbound Destination NAT (DNAT):\n"
            "  - Original Packet: Destination Public IP 198.51.100.1:443.\n"
            "  - Translated Packet: Destination Trust-DMZ ALB 10.100.4.15:443.\n"
            "  - Protects internal IP addressing from external discovery.\n\n"
            "• Outbound Source PAT (Port Overload):\n"
            "  - Internal Workload CIDR 10.100.0.0/16 translated to external perimeter public interface IP with dynamic source port mapping.\n\n"
            "• Security Objects Library:\n"
            "  - 12 Address Objects & 3 Address Groups (addr-grp-internal-networks, addr-grp-prod-workloads).\n"
            "  - 10 Service Objects & 2 Service Groups (svc-grp-web-standard, svc-grp-database-ports).",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=8)


# --- SLIDE 7: Panorama Central Management Architecture (Light Theme) ---
def build_slide_07():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Device Groups, Template Stacks & Centralized Commit Pipeline", "Panorama Architecture", 7)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "Central Management Appliance",
            "pan-mgmt-01 (M-600 Virtual Instance)",
            C_PANORAMA,
            "• Server Details:\n"
            "  - Hostname: pan-mgmt-01.mgmt.apex-global.example\n"
            "  - IP Address: 10.254.1.10 (Zone: Mgmt-OOB / VLAN 254)\n"
            "  - OS Version: PAN-OS 11.1 Nebula\n"
            "  - Deployment: Standalone Virtual Appliance (M-600 profile)\n\n"
            "• Governed Administrator Access:\n"
            "  - Central Superuser Write governed by SailPoint ISC via entitlement sp-ent-panos-admin-write (held by David Kim).\n"
            "  - Read-Only Security Auditor governed via access profile sp-ap-paloalto-firewall-audit.\n\n"
            "• Communication Security:\n"
            "  - Dedicated SSL/TLS mutual authentication over TCP 3978 between Panorama and managed firewalls.",
        ),
        (
            "Device Group & Template Stacks",
            "Modular Configuration Hierarchy",
            C_SAILPOINT,
            "• Device Group Tree:\n"
            "  - Shared: Base address objects, service groups, compliance pre-rules.\n"
            "  - DG-Internet-Perimeter: Pushed to fw-edge-01 and fw-edge-02.\n"
            "  - DG-Internal-Segmentation: Pushed to fw-internal-01 and fw-internal-02.\n\n"
            "• Template Stacks Architecture:\n"
            "  - TPL-Global-Baseline: Corporate DNS (10.10.1.10, 10.10.1.11), NTP servers, syslog forwarders, SNMPv3 credentials.\n"
            "  - TPL-Edge-Networking: Physical ethernet1/1-4, VR vr-default-edge.\n"
            "  - TPL-Internal-Networking: Physical ethernet1/1-6, VR vr-internal-core.\n"
            "  - STACK-Edge-Firewalls & STACK-Internal-Firewalls combine baseline + network templates seamlessly.",
        ),
        (
            "Commit Pipeline & Audit Logs",
            "Change Management & Observability",
            C_WORKLOAD,
            "• Two-Stage Commit Pipeline:\n"
            "  - Candidate Configuration: Administrators propose rule updates.\n"
            "  - Pre-Commit Validation: Verifies syntax, address object resolution, and zone reachability.\n"
            "  - Panorama Commit: Deploys candidate config to central store.\n"
            "  - Device Push: Transmits compiled rulebases to target firewall HA pairs with automatic rollback on failure.\n\n"
            "• Audit Logging & Observability:\n"
            "  - Config Audit Log: Records admin ID, timestamp, and XML diff.\n"
            "  - Unified Log Ingestion: Ingests Traffic, Threat, System, and HIP logs from all firewalls, forwarded to SecOps SIEM.",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=8)


# --- SLIDE 8: Network Security Zones & Micro-Segmentation (Light Theme) ---
def build_slide_08():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "9 Enterprise Security Zones & Zero-Trust Boundary Matrix", "Network Security Zones", 8)

    zones_headers = ["Zone Name", "Zone ID", "Primary Subnet", "Criticality", "Allowed Ingress Protocols", "Strict Security Guardrail"]
    zones_rows = [
        ["Untrust-Internet", "zone-untrust-internet", "Public / 0.0.0.0/0", "Low", "HTTPS (443), GlobalProtect VPN", "Edge ingress terminated; anti-spoofing drop"],
        ["Trust-DMZ", "zone-trust-dmz", "10.100.4.0/24 (VLAN 104)", "High", "HTTPS (443), Telemetry Ingest", "Direct traffic to Database-Backend strictly blocked"],
        ["Corp-Users", "zone-corp-users", "10.10.0.0/16 (VLAN 10)", "High", "Web Browsing, Internal Apps", "User-ID inspected; blocked from PCI & Vault zones"],
        ["Transit-Internal", "zone-transit-internal", "10.255.0.0/30 (VLAN 255)", "High", "Point-to-Point Routing", "Inter-firewall backbone; no host workloads allowed"],
        ["Prod-App-Workloads", "zone-prod-app-workloads", "10.100.10.0/23 (VLAN 110)", "High", "HTTP (8080), gRPC, Microservices", "EKS pods isolated by Kubernetes NetworkPolicies"],
        ["Dev-App-Workloads", "zone-dev-app-workloads", "10.200.10.0/23 (VLAN 210)", "Medium", "Dev Web, Ephemeral Test APIs", "Strictly prohibited from accessing Production App or DB"],
        ["Database-Backend", "zone-database-backend", "10.100.20.0/24 (VLAN 120)", "Critical", "PostgreSQL (5432)", "Inbound permitted ONLY from Prod-App pods"],
        ["PCI-Cardholder-Data", "zone-pci-cardholder-data", "10.100.30.0/24 (VLAN 130)", "Critical", "mTLS Token API (8443), DB (5432)", "Strict PCI DSS 4.0 enclave; no direct Internet access"],
        ["Restricted-Data-Vault", "zone-restricted-data-vault", "10.100.40.0/24 (VLAN 140)", "Critical", "HTTPS (443) via VPC S3 Endpoint", "NIST SP 800-171 CUI financial vault isolation"],
    ]
    col_w = [Inches(1.6), Inches(1.8), Inches(1.5), Inches(0.9), Inches(2.2), Inches(3.733)]
    add_table_grid(slide, Inches(0.8), Inches(1.35), Inches(11.733), Inches(4.3), zones_headers, zones_rows, col_w, header_bg=C_NAVY_DARK)

    # Bottom Guardrail Summary
    add_card(
        slide,
        Inches(0.8),
        Inches(5.8),
        Inches(11.733),
        Inches(1.15),
        title="ZERO-TRUST MICRO-SEGMENTATION GUARDRAILS",
        subtitle=(
            "• Default Deny Everywhere: All inter-zone and intra-zone communications are blocked by default unless explicitly permitted by Panorama rules.\n"
            "• Tier Separation: Public DMZ hosts can NEVER directly communicate with Database-Backend or PCI-Cardholder-Data without traversing the Prod-App tier.\n"
            "• Threat Prevention Enforcement: All inter-zone permit rules enforce the 'Strict-Enterprise-Security' profile group (anti-spyware, IPS, and anti-virus)."
        ),
        bg_color=RGBColor(241, 245, 249),
        border_color=C_FIREWALL,
        title_color=C_FIREWALL,
        title_size=9.5,
        sub_size=8,
    )


# --- SLIDE 9: AWS Multi-Account Organisation & Structure (Light Theme) ---
def build_slide_09():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "AWS Organizations, OUs, SCP Guardrails & Cross-Account Trust", "AWS Multi-Account", 9)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "Account: 111122223333",
            "Apex-Production (OU: Workloads)",
            C_AWS,
            "• Account Scope & Role:\n"
            "  Primary revenue-generating account hosting all customer-facing applications and sensitive data vaults.\n\n"
            "• Core VPC & Networking:\n"
            "  VPC: vpc-prod-us-east-1 (10.100.0.0/16)\n"
            "  Subnets: DMZ (10.100.4.0/24), App (10.100.10.0/23), DB (10.100.20.0/24), PCI (10.100.30.0/24), Vault (10.100.40.0/24).\n\n"
            "• Workload Compute:\n"
            "  - eks-customer-portal-cluster (Customer Web Portal)\n"
            "  - eks-analytics-worker-pool (Analytics Ingestion)\n"
            "  - eks-payment-processor-pool (PCI DSS Tokenizer)\n"
            "  - alb-customer-portal-ingress (Public ALB Ingress)\n\n"
            "• Databases & Data Stores:\n"
            "  - rds-postgres-core-prod (Customer Relational DB)\n"
            "  - rds-pci-token-vault-prod (Payment Token DB)\n"
            "  - s3-enterprise-cui-vault (CUI Financial Vault)",
        ),
        (
            "Account: 222233334444",
            "Apex-Development (OU: Workloads)",
            C_DEV,
            "• Account Scope & Role:\n"
            "  Developer sandbox, staging microservices, and non-sensitive test environments for rapid feature delivery.\n\n"
            "• Core VPC & Networking:\n"
            "  VPC: vpc-dev-us-east-1 (10.200.0.0/16)\n"
            "  Subnet: subnet-dev-app-01 (10.200.10.0/23)\n"
            "  Security Group: sg-dev-k8s-nodes\n\n"
            "• Workload Compute:\n"
            "  - eks-dev-cluster: Multi-tenant developer Kubernetes cluster hosting ephemeral microservices.\n\n"
            "• Storage & Telemetry:\n"
            "  - s3-dev-staging-telemetry: Ingestion bucket for de-identified staging logs and test artifacts.\n\n"
            "• Governance Guardrails:\n"
            "  Strictly isolated from Production account; developers holding PowerUserAccess cannot cross account boundaries.",
        ),
        (
            "Account: 333344445555",
            "Apex-Security (OU: Security)",
            C_SECOPS,
            "• Account Scope & Role:\n"
            "  Centralized security operations, multi-account CloudTrail log archiving, GuardDuty, and incident response tooling.\n\n"
            "• Core VPC & Networking:\n"
            "  VPC: vpc-sec-us-east-1 (10.250.0.0/16)\n"
            "  Subnet: subnet-sec-audit-01 (10.250.1.0/24)\n"
            "  Security Group: sg-sec-siem-forwarder\n\n"
            "• Compute & Forwarders:\n"
            "  - ec2-sec-siem-forwarder: Dedicated hardened EC2 instance collecting multi-account CloudTrail, VPC Flow Logs & PAN-OS syslog.\n\n"
            "• Immutable Audit Vault:\n"
            "  - s3-central-security-cloudtrail-sec: Multi-account CloudTrail aggregation bucket with Object Lock & KMS encryption.\n\n"
            "• SecOps IAM Role:\n"
            "  role-secops-incident-responder assumes cross-account read-only audit roles in Prod and Dev.",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=7.5)


# --- SLIDE 10: AWS Cloud Infrastructure & Workloads (Light Theme) ---
def build_slide_10():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Compute Workloads, Relational Databases, S3 Storage & KMS", "AWS Infrastructure", 10)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "Compute Workloads (5 Assets)",
            "EKS Clusters & Hardened EC2",
            C_WORKLOAD,
            "• eks-customer-portal-cluster:\n"
            "  Production EKS cluster hosting Customer Web Portal (APP-001) and API Gateway (APP-007). Assumes role-customer-portal-backend via IRSA.\n\n"
            "• eks-analytics-worker-pool:\n"
            "  EKS analytics cluster in Trust-DMZ hosting Customer Analytics (APP-003) and Data Ingestion (APP-009). Assumes role-analytics-ingestion-svc.\n\n"
            "• eks-payment-processor-pool:\n"
            "  Isolated EKS cluster in PCI Cardholder zone hosting Payment Processing (APP-002). Assumes role-payment-processor-pci.\n\n"
            "• eks-dev-cluster:\n"
            "  Non-production EKS cluster in Development account hosting Internal Developer Platform (APP-011).\n\n"
            "• ec2-sec-siem-forwarder:\n"
            "  Hardened EC2 instance in Security account running Central SIEM & SOC Monitoring (APP-010).",
        ),
        (
            "Databases & Storage (7 Assets)",
            "RDS PostgreSQL & S3 Buckets",
            C_AWS,
            "• rds-postgres-core-prod:\n"
            "  Multi-AZ PostgreSQL cluster in Database-Backend zone storing customer profiles & transactions. Encrypted by kms-customer-db.\n\n"
            "• rds-pci-token-vault-prod:\n"
            "  Strictly isolated PostgreSQL database storing payment card token mappings. Encrypted by HSM-backed kms-pci-token.\n\n"
            "• s3-enterprise-cui-vault:\n"
            "  Restricted S3 bucket storing NIST SP 800-171 Controlled Unclassified Information. Encrypted by kms-cui-vault.\n\n"
            "• s3-customer-pii-lake-prod:\n"
            "  Production data lake storing customer analytics & HR archives.\n\n"
            "• s3-pci-audit-records-prod:\n"
            "  Immutable PCI DSS compliance audit records.\n\n"
            "• s3-central-security-cloudtrail-sec:\n"
            "  Centralized multi-account CloudTrail log vault.",
        ),
        (
            "Encryption & KMS Keys (3 Keys)",
            "Envelope Encryption & CMKs",
            C_DATA,
            "• kms-cui-vault:\n"
            "  - Alias: alias/apex-cui-vault-key\n"
            "  - Algorithm: SYMMETRIC_DEFAULT (AES-256)\n"
            "  - Key Policy: Scoped strictly to S3 CUI Financial Vault\n"
            "  - Automatic annual key rotation enabled.\n\n"
            "• kms-pci-token:\n"
            "  - Alias: alias/apex-pci-token-key\n"
            "  - Hardware Security Module (HSM) backed (FIPS 140-2 Level 3)\n"
            "  - Decrypt permissions strictly constrained to Payment Processor IRSA role under policy KmsDecryptPaymentScoped.\n\n"
            "• kms-customer-db:\n"
            "  - Alias: alias/apex-rds-customer-key\n"
            "  - XTS-AES-256 storage volume encryption for PostgreSQL\n"
            "  - Automated RDS snapshot & cross-region backup encryption.",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=7.5)


# --- SLIDE 11: SailPoint Identity Security Cloud Architecture (Light Theme) ---
def build_slide_11():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Central Identity Governance, Connected Sources & Entity Models", "SailPoint ISC Architecture", 11)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "Authoritative Tenant & Sources",
            "sp-tenant-apexglobal-01",
            C_SAILPOINT,
            "• SailPoint Tenant Details:\n"
            "  - Tenant ID: sp-tenant-apexglobal-01\n"
            "  - Domain: apexglobal.identitynow.example (AWS us-east-1)\n"
            "  - Version: 2026.1 (Cloud-Federated IGA)\n\n"
            "• 8 Connected Target Sources:\n"
            "  1. sp-src-active-directory (Corporate Active Directory)\n"
            "  2. sp-src-entra-id (Microsoft Entra ID Cloud SSO)\n"
            "  3. sp-src-aws-prod (AWS Production Account 111122223333)\n"
            "  4. sp-src-aws-dev (AWS Development Account 222233334444)\n"
            "  5. sp-src-aws-secops (AWS Security Account 333344445555)\n"
            "  6. sp-src-enterprise-apps (Enterprise Applications)\n"
            "  7. sp-src-database-platform (PostgreSQL DB Platform)\n"
            "  8. sp-src-firewall-mgmt (Palo Alto Panorama Mgmt)",
        ),
        (
            "Identity Profiles & Identities",
            "4 Profiles & 22 Authoritative Identities",
            C_WORKLOAD,
            "• 4 Authoritative Identity Profiles:\n"
            "  - sp-idp-corporate-employees: Full-time personnel\n"
            "  - sp-idp-external-contractors: Time-bound vendors\n"
            "  - sp-idp-privileged-admins: High-assurance administrators\n"
            "  - sp-idp-service-identities: Machine service principals\n\n"
            "• 22 Representative Identities:\n"
            "  - Sarah Chen: Chief Information Security Officer (CISO)\n"
            "  - Marcus Vance: Principal Enterprise Architect\n"
            "  - Elena Rodriguez: Lead SecOps Incident Responder\n"
            "  - David Kim: Network Security Engineer\n"
            "  - Emily Watson: Senior Treasury Analyst\n"
            "  - Alex Morgan: Cloud Platform Lead\n"
            "  - Priya Patel: Lead DevOps SRE\n"
            "  - Carlos Mendez: Lead Database Administrator",
        ),
        (
            "Identity vs. Account Disambiguation",
            "Governance vs. Runtime Enforcement",
            C_DATA,
            "• Foundational Identity Model: Identity != Account\n"
            "  - Identity (SailPoint_Identity): Single physical human or service principal across the enterprise.\n"
            "  - Account (SailPoint_Account): Target-specific credential owned by an identity across connected sources (OWNS_ACCOUNT).\n"
            "  - Example: Sarah Chen owns 3 accounts (AD s.chen, Entra ID sarah.chen@apex-global.example, and AWS SecOps user sarah.chen-exec).\n\n"
            "• Governance vs. Runtime Enforcement:\n"
            "  - SailPoint ISC governs WHO should have access and WHY.\n"
            "  - Governed via GOVERNED_BY_SAILPOINT relationship.\n"
            "  - AWS IAM and PAN-OS enforce runtime packet and API authorization; SailPoint does NOT replace AWS resource policies.",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=7.5)


# --- SLIDE 12: Identity Governance Lifecycle, Roles & Access Policies (Light Theme) ---
def build_slide_12():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Three-Tier RBAC Hierarchy, Access Requests & Provisioning Gates", "Identity Lifecycle & RBAC", 12)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "Three-Tier RBAC Hierarchy",
            "Roles -> Access Profiles -> Entitlements",
            C_SAILPOINT,
            "• 9 Business & IT Roles (SailPoint_Role):\n"
            "  - Finance & Treasury Analyst (sp-role-finance-analyst)\n"
            "  - Network Security Engineer (sp-role-network-security-engineer)\n"
            "  - Cloud Administrator (sp-role-cloud-administrator)\n"
            "  - Production Support SRE, Software Developer, SecOps Analyst, DBA, Compliance Auditor, Payment Card Custodian.\n\n"
            "• 11 Access Profiles (SailPoint_AccessProfile):\n"
            "  - Group entitlements per connected source.\n"
            "  - sp-ap-aws-prod-s3-read (S3 CUI Vault Read Access)\n"
            "  - sp-ap-paloalto-firewall-admin (Panorama Superuser)\n"
            "  - sp-ap-aws-prod-admin (AWS Root AdministratorAccess)\n\n"
            "• 13 Granular Entitlements (SailPoint_Entitlement):\n"
            "  - sp-ent-aws-s3-cui-read: s3:GetObject on CUI vault\n"
            "  - sp-ent-panos-admin-write: Panorama Superuser write\n"
            "  - sp-ent-db-core-read: SQL SELECT on customer DB",
        ),
        (
            "Access Requests & Approvals",
            "Multi-Stage Compliance Workflows",
            C_FIREWALL,
            "• 5 Access Request Workflow Scenarios:\n"
            "  1. sp-req-1001: Approved standard access (Emily Watson for S3 CUI Read; approved by CISO Sarah Chen).\n"
            "  2. sp-req-1002: Rejected access (Contractor Sophia Alvarez requested AWS Root Admin; explicitly rejected by Cloud Lead under least-privilege policy SEC-IAM-004).\n"
            "  3. sp-req-1003: Pending access (Developer Vikram Sharma requested Cloud Admin; awaiting manager & CISO approval).\n"
            "  4. sp-req-1004: Emergency break-glass (David Kim requested elevated firewall access during DDoS incident; time-limited to 4 hours).\n"
            "  5. sp-req-1005: Access revocation (Contractor Liam O'Connor database access revoked upon project completion).\n\n"
            "• Multi-Stage Approval Chain:\n"
            "  Manager Review -> Resource Security Owner -> CISO Executive Gate.",
        ),
        (
            "Provisioning Gates & Certifications",
            "Strict Traversal Rules in SimuGuard AI",
            C_WORKLOAD,
            "• Governance Traversal Rules:\n\n"
            "• Rule 1: PENDING_IS_NOT_ACCESS:\n"
            "  In-flight requests in PENDING_APPROVAL status (such as sp-req-1003) convey ZERO effective permissions. SimuGuard AI NEVER propagates blast radius across pending access requests.\n\n"
            "• Rule 2: PROVISIONING_GATE:\n"
            "  Request approval is a governance mandate, but access is only operationally realized when downstream reconciliation confirms PROVISIONED state on target.\n\n"
            "• Rule 3: CERTIFICATION_REVOCATION_RECONCILIATION:\n"
            "  Certification decision to revoke access (sp-cert-2025-q4-dormant-revoked) is not proof of deprovisioning until source reconciliation confirms removal.\n\n"
            "• 5 Periodic Certification Campaigns:\n"
            "  Q1 Privileged Review, PCI DSS Semi-Annual, Contractor Audit, Dormant Cleanup, and Expired Emergency Review.",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=7.5)


# --- SLIDE 13: Enterprise Application Architecture (Light Theme) ---
def build_slide_13():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "12 Business Applications, Workload Hosts & API Dependencies", "Application Architecture", 13)

    apps_headers = ["App ID", "Application Name", "Tier", "Hosted Workload Cluster", "Zone", "Service Dependencies"]
    apps_rows = [
        ["APP-001", "Customer Web Portal", "Tier 1", "eks-customer-portal-cluster", "Prod-App", "Calls API Gateway (APP-007) & IdP (APP-006)"],
        ["APP-002", "PCI Payment Processing Service", "Tier 1", "eks-payment-processor-pool", "PCI-Cardholder", "Consumed by Order Settlement Engine (APP-008)"],
        ["APP-003", "Customer Telemetry & Analytics", "Tier 2", "eks-analytics-worker-pool", "Trust-DMZ", "Fed by Data Ingestion (APP-009); feeds Financial Reporting"],
        ["APP-004", "Human Resources & Payroll Portal", "Tier 3", "eks-customer-portal-cluster", "Prod-App", "Connects to Employee HR Records Bucket"],
        ["APP-005", "Core Financial Reporting & General Ledger", "Tier 2", "eks-analytics-worker-pool", "Trust-DMZ", "Reads from CUI Financial Vault (s3-enterprise-cui-vault)"],
        ["APP-006", "Enterprise Identity & IAM (IdP)", "Tier 1", "sp-tenant-apexglobal-01", "Cloud SSO", "Provides SAML/OIDC SSO federation to Portal (APP-001)"],
        ["APP-007", "Core Enterprise API Gateway", "Tier 1", "eks-customer-portal-cluster", "Trust-DMZ", "Central routing proxy for Portal, Order Mgmt & Dev Platform"],
        ["APP-008", "Order Management & Settlement Engine", "Tier 2", "eks-customer-portal-cluster", "Prod-App", "Dispatches payment card tokenization to APP-002"],
        ["APP-009", "Global Data Ingestion Pipeline", "Tier 2", "eks-analytics-worker-pool", "Trust-DMZ", "Kafka event streaming into Analytics (APP-003)"],
        ["APP-010", "Central Security SIEM & SOC Monitoring", "Tier 2", "ec2-sec-siem-forwarder", "Security", "Aggregates multi-account CloudTrail & feeds GRC (APP-012)"],
        ["APP-011", "Internal Developer Platform (IDP)", "Tier 3", "eks-dev-cluster", "Dev-App", "Non-production staging calling API Gateway test mocks"],
        ["APP-012", "GRC Continuous Audit & Compliance Engine", "Tier 3", "ec2-sec-siem-forwarder", "Security", "Consumes SIEM events for SOX 404 & PCI compliance scans"],
    ]
    col_w = [Inches(1.0), Inches(2.3), Inches(0.8), Inches(2.2), Inches(1.3), Inches(4.133)]
    add_table_grid(slide, Inches(0.8), Inches(1.35), Inches(11.733), Inches(5.6), apps_headers, apps_rows, col_w, header_bg=C_NAVY_DARK)


# --- SLIDE 14: Sensitive Data Architecture & Classifications (Light Theme) ---
def build_slide_14():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "5 Data Classification Tiers & 6 Enterprise Data Repositories", "Data Architecture", 14)

    # Left: 5 Classification Tiers
    add_card(
        slide,
        Inches(0.8),
        Inches(1.35),
        Inches(4.6),
        Inches(5.6),
        title="DATA CLASSIFICATION TIERS & CONTROLS",
        subtitle=(
            "1. RESTRICTED_CUI_PII (Critical Sensitivity):\n"
            "• Scope: NIST SP 800-171 Controlled Unclassified Information, general ledger financial records, and master audit logs.\n"
            "• Controls: Customer-managed KMS encryption (kms-cui-vault), MFA-Delete on S3 buckets, TLS 1.3 in transit, strict IAM least privilege.\n\n"
            "2. PCI_CARDHOLDER_DATA (Critical Sensitivity):\n"
            "• Scope: Primary Account Numbers (PAN), CVV hashes, and tokenization database records.\n"
            "• Controls: PCI DSS 4.0 Req 3/7 enclave isolation, Hardware Security Module (HSM) backed kms-pci-token, dedicated subnet isolation.\n\n"
            "3. CONFIDENTIAL_PII (High Sensitivity):\n"
            "• Scope: Customer profiles, billing addresses, employee HR payroll & medical benefits.\n"
            "• Controls: GDPR Article 32, CCPA, SOC 2 Type II compliance, RDS PostgreSQL storage encryption (kms-customer-db).\n\n"
            "4. INTERNAL_OPERATIONAL (Medium Sensitivity):\n"
            "• Scope: System telemetry, de-identified application logs, non-production staging data.\n\n"
            "5. PUBLIC_UNRESTRICTED (Low Sensitivity):\n"
            "• Scope: Marketing collateral, public website assets, static portal documentation."
        ),
        bg_color=C_CARD_BG,
        border_color=C_DATA,
        title_color=C_DATA,
        title_size=10.5,
        sub_size=7.5,
    )

    # Right: 6 Core Data Assets Table
    data_headers = ["Asset ID", "Asset Name", "Classification", "Storage Repository", "Compliance Frameworks"]
    data_rows = [
        ["DATA-01", "CUI Financial Vault", "RESTRICTED_CUI_PII", "s3-enterprise-cui-vault (S3)", "NIST SP 800-171, SOX 404, SOC 2"],
        ["DATA-02", "PCI Token Vault", "PCI_CARDHOLDER_DATA", "rds-pci-token-vault-prod (RDS)", "PCI DSS 4.0 Req 3, 7, 10"],
        ["DATA-03", "Customer PII Database", "CONFIDENTIAL_PII", "rds-postgres-core-prod (RDS)", "GDPR Art 32, CCPA, SOC 2"],
        ["DATA-04", "Employee HR Records", "CONFIDENTIAL_PII", "s3-customer-pii-lake-prod (S3)", "GDPR, EEOC, SOC 2"],
        ["DATA-05", "Central Security Logs", "RESTRICTED_CUI_PII", "s3-central-security-cloudtrail-sec", "NIST SP 800-53 AU-9, SOX 404"],
        ["DATA-06", "Dev Staging Telemetry", "INTERNAL_OPERATIONAL", "s3-dev-staging-telemetry (S3)", "Internal Operational Baseline"],
    ]
    col_w = [Inches(1.0), Inches(1.8), Inches(1.5), Inches(1.6), Inches(1.033)]
    add_table_grid(slide, Inches(5.6), Inches(1.35), Inches(6.933), Inches(5.6), data_headers, data_rows, col_w, header_bg=C_NAVY_DARK)


# --- SLIDE 15: End-to-End Dependency Flow & Multi-Hop Attack Path (Light Theme) ---
def build_slide_15():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Cross-Layer Lateral Movement Path & Access Verification", "Dependency Architecture", 15)

    step_w = Inches(2.23)
    step_gap = Inches(0.14)
    y_step = Inches(1.35)
    step_h = Inches(4.3)

    steps = [
        (
            "1. Network Ingress",
            "Perimeter Firewall Layer",
            C_FIREWALL,
            "• Traffic Source:\n"
            "  External untrusted user initiates traffic toward public IP 198.51.100.1.\n\n"
            "• Firewall Inspection:\n"
            "  fw-edge-01-primary evaluates rulebase.\n\n"
            "• Vulnerability Trigger:\n"
            "  Terraform change adds rule bypassing App-ID (application 'any' and destination 'any').\n\n"
            "• Ingress Routing:\n"
            "  Traffic translated to subnet-prod-dmz-01 (Trust-DMZ).",
        ),
        (
            "2. Workload & App",
            "Kubernetes Pod Layer",
            C_WORKLOAD,
            "• Workload Location:\n"
            "  Trust-DMZ contains compute workload eks-analytics-worker-pool.\n\n"
            "• Application Binding:\n"
            "  Workload hosts APP-003-CUSTOMER-ANALYTICS.\n\n"
            "• Impact Status:\n"
            "  Pod inherits uninspected outbound egress pathway.\n\n"
            "• Direct/Cascading:\n"
            "  Pod compromised or utilized as lateral pivot point.",
        ),
        (
            "3. SailPoint IGA",
            "Identity Governance Plane",
            C_SAILPOINT,
            "• Identity Entity:\n"
            "  sp-ident-emily-watson (Senior Treasury Analyst).\n\n"
            "• RBAC Mapping:\n"
            "  Identity is assigned sp-role-finance-analyst.\n\n"
            "• Access Profile:\n"
            "  Role groups sp-ap-aws-prod-s3-read.\n\n"
            "• Entitlement:\n"
            "  Contains sp-ent-aws-s3-cui-read (s3:GetObject on CUI vault).\n\n"
            "• Governed Access:\n"
            "  Authorizes read access in governance registry.",
        ),
        (
            "4. AWS Runtime IAM",
            "Pod Federation & IAM Roles",
            C_AWS,
            "• Pod Federation (IRSA):\n"
            "  eks-analytics-worker-pool assumes role-analytics-ingestion-svc via EKS OIDC provider.\n\n"
            "• Policy Attachment:\n"
            "  Terraform PR mistakenly attaches broad policy (e.g. AmazonS3FullAccess).\n\n"
            "• Cross-Zone Path:\n"
            "  CROSS_ZONE_IAM_PATH blast condition satisfied between DMZ pod and Production S3.",
        ),
        (
            "5. Data Asset",
            "Target Sensitive Vault",
            C_DATA,
            "• Storage Resource:\n"
            "  Target bucket is s3-enterprise-cui-vault (Zone: Restricted-Vault).\n\n"
            "• Data Repository:\n"
            "  Stores DATA-01-CUI-FINANCIAL-VAULT (NIST SP 800-171 CUI).\n\n"
            "• Business Impact:\n"
            "  Unauthorized exfiltration of general ledger & treasury data.\n\n"
            "• SimuGuard Verdict:\n"
            "  BLOCK_DEPLOYMENT issued.",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(steps):
        x = Inches(0.8) + idx * (step_w + step_gap)
        add_card(slide, x, y_step, step_w, step_h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=10, sub_color=C_TEXT_DARK, sub_size=7.5)

    # Bottom Methodology Banner
    add_card(
        slide,
        Inches(0.8),
        Inches(5.8),
        Inches(11.733),
        Inches(1.2),
        title="METHODOLOGY: CONFIGURED vs. INFERRED vs. OBSERVED RELATIONSHIPS",
        subtitle=(
            "• Configured Relationships: Explicitly declared in dataset (e.g., MEMBER_OF_ROLE, OWNS_ACCOUNT, ENFORCES_ZONE_POLICY).\n"
            "• Inferred Linkages: Derived by Digital Twin graph engine based on implicit infrastructure bindings (e.g., CONTAINS_WORKLOAD, ASSUMES_ROLE via IRSA).\n"
            "• Observed Access: Governance alone does NOT prove runtime access until downstream target provisioning is verified on source (PROVISIONED)."
        ),
        bg_color=RGBColor(241, 245, 249),
        border_color=C_SAILPOINT,
        title_color=C_SAILPOINT,
        title_size=9,
        sub_size=7.5,
    )


# --- SLIDE 16: Security Boundaries & Trust Relationships (Light Theme) ---
def build_slide_16():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Defense-in-Depth Trust Boundaries & Permission Envelopes", "Security Boundaries", 16)

    card_w = Inches(5.74)
    card_h = Inches(2.7)

    # 4 Quadrants
    quads = [
        (
            Inches(0.8),
            Inches(1.35),
            "1. Network Security Boundaries",
            "Perimeter & Internal Firewall Zones",
            C_FIREWALL,
            "• Untrust-Internet Boundary: Enforced by PA-5450 HA pair at physical ingress. Blocks unapproved ports, inbound spoofing, and malware payloads.\n"
            "• Internal Segmentation Boundary: Enforced by PA-3440 HA pair across point-to-point interconnect. Isolates database and PCI zones.\n"
            "• Microsegmentation: Intra-zone zero trust blocks lateral movement between containerized pods in the same subnet.",
        ),
        (
            Inches(6.78),
            Inches(1.35),
            "2. Cloud Infrastructure Boundaries",
            "Multi-Account Isolation & VPC Controls",
            C_AWS,
            "• AWS Organization Boundary: o-apexglobal01 enforces Service Control Policies (SCPs) preventing CloudTrail disabling and unauthorized region usage.\n"
            "• Account Isolation: Strict blast isolation between Production (111122223333), Development (222233334444), and Security (333344445555).\n"
            "• Network ACLs & Security Groups: Least-privilege inbound/egress rules on all compute workloads.",
        ),
        (
            Inches(0.8),
            Inches(4.25),
            "3. Identity & Governance Boundaries",
            "SailPoint ISC & Federated Identity",
            C_SAILPOINT,
            "• Authoritative Source Boundaries: Corporate Active Directory and Microsoft Entra ID act as authoritative identity sources.\n"
            "• SailPoint Tenant Boundary: sp-tenant-apexglobal-01 governs all access requests, managerial approvals, and periodic certification reviews.\n"
            "• Pod Federation Boundary: EKS IRSA OIDC federation avoids static AWS IAM access keys inside container pods.",
        ),
        (
            Inches(6.78),
            Inches(4.25),
            "4. Permission & Privilege Boundaries",
            "Least Privilege & IAM Permission Boundaries",
            C_DATA,
            "• IAM Permission Boundaries: ApexWorkloadBoundary and ApexStrictPCIBoundary define maximum possible permissions for workload roles.\n"
            "• Data Protection Envelopes: KMS Customer Managed Keys (CMKs) enforce strict separation of duties (KMS Decrypt separated from S3 Read).\n"
            "• PCI DSS Enclave: Tokenization database strictly inaccessible from non-payment microservices.",
        ),
    ]

    for x, y, title, sub, col, text in quads:
        add_card(slide, x, y, card_w, card_h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=8)


# --- SLIDE 17: SimuGuard AI Platform Architecture (Light Theme) ---
def build_slide_17():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Pre-Deployment Digital Twin, Graph Traversal & Policy Gates", "SimuGuard AI Platform", 17)

    card_w = Inches(3.75)
    card_gap = Inches(0.24)
    h = Inches(5.6)

    cols = [
        (
            "1. Ingestion & Normalization",
            "Terraform HCL Change Parser",
            C_FIREWALL,
            "• python-hcl2 Parsing Engine:\n"
            "  Parses all Terraform .tf changes into structured Python Pydantic objects.\n\n"
            "• Normalized Resource Models:\n"
            "  - panos_security_policy (Palo Alto firewall security rules)\n"
            "  - aws_security_group_rule (AWS VPC egress/ingress rules)\n"
            "  - aws_iam_role_policy_attachment (IAM role attachments)\n\n"
            "• Error Distinction:\n"
            "  Gracefully separates HCL syntax errors from Terraform provider schema validation errors.\n\n"
            "• Batch & Single File Processing:\n"
            "  Supports scanning individual pull request diffs or entire configuration directories.",
        ),
        (
            "2. Digital Twin Graph",
            "NetworkX Graph Traversal Engine",
            C_SAILPOINT,
            "• Dynamic Topology Graph:\n"
            "  Loads 220 infrastructure nodes and 77 directed edges into a unified NetworkX directed graph.\n\n"
            "• Blast Radius Traversal:\n"
            "  - Evaluates direct impacts (nodes directly targeted by change).\n"
            "  - Traverses cascading impacts along conditional edges (App-ID bypass, overprivileged S3 policies, cross-account trust).\n\n"
            "• UNKNOWN Status Guardrail:\n"
            "  Unmapped resources produce ImpactStatus.UNKNOWN.\n"
            "  Missing topology relationships are NEVER treated as proof of isolation or safety.",
        ),
        (
            "3. Security Rules & Verdict",
            "Automated Deployment Gate",
            C_WORKLOAD,
            "• Security Rule Engine:\n"
            "  - Detects wildcard 0.0.0.0/0 egress without App-ID.\n"
            "  - Detects disabled NGFW threat prevention profiles.\n"
            "  - Detects broad S3FullAccess attachments on DMZ roles.\n"
            "  - Detects cross-account trust privilege escalation.\n\n"
            "• Quantitative Risk Scoring:\n"
            "  Calculates risk score between 0 and 100 based on asset criticality, vulnerability severity, and blast radius.\n\n"
            "• Pre-Flight Deployment Verdicts:\n"
            "  - ALLOW (0-39): Safe deployment\n"
            "  - WARN_MANUAL_REVIEW (40-69): Human review needed\n"
            "  - BLOCK_DEPLOYMENT (70-100): Critical risk blocked",
        ),
    ]

    for idx, (title, sub, col, text) in enumerate(cols):
        x = Inches(0.8) + idx * (card_w + card_gap)
        add_card(slide, x, Inches(1.35), card_w, h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=11, sub_color=C_TEXT_DARK, sub_size=7.5)


# --- SLIDE 18: Future Integration Roadmap (Light Theme) ---
def build_slide_18():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Planned Live Platform Connectors & Enterprise Integrations", "Future Roadmap", 18)

    # Prominent Warning Banner: Planned Roadmap Only
    add_card(
        slide,
        Inches(0.8),
        Inches(1.35),
        Inches(11.733),
        Inches(0.55),
        title="⚠️ PLANNED ROADMAP ONLY — NOT ACTIVE IN CURRENT DIGITAL TWIN BENCHMARK",
        subtitle="The items below represent future production platform integrations. All current SimuGuard AI testing is executed against the synthetic enterprise benchmark.",
        bg_color=RGBColor(254, 242, 242),
        border_color=C_FIREWALL,
        title_color=C_FIREWALL,
        title_size=9.5,
        sub_size=7.5,
    )

    card_w = Inches(5.74)
    card_h = Inches(2.4)
    y_r1 = Inches(2.05)
    y_r2 = Inches(4.65)

    quads = [
        (
            Inches(0.8),
            y_r1,
            "1. Live Palo Alto Panorama XML API Integration",
            "Automated Rule Audit & Dry-Run Validation (Planned)",
            C_FIREWALL,
            "• Bidirectional API Synchronization:\n"
            "  Connect via Panorama XML API to pull live running candidate configurations, address object hierarchies, and security policy rulebases.\n"
            "• Pre-Commit Dry Run Testing:\n"
            "  Simulate proposed Panorama commits in virtual test environments before committing to physical edge and internal firewalls.\n"
            "• Policy Shadowing Detection:\n"
            "  Real-time algorithmic detection of shadowed or redundant firewall security rules.",
        ),
        (
            Inches(6.78),
            y_r1,
            "2. Live SailPoint ISC REST API v3 Integration",
            "Real-Time Identity Governance Synchronization (Planned)",
            C_SAILPOINT,
            "• Real-Time Source Identity Sync:\n"
            "  Connect via SailPoint ISC REST API v3 to ingest live identity profiles, accounts, and role assignment matrices.\n"
            "• Automated Certification Triggering:\n"
            "  Automatically trigger targeted SailPoint access certification campaigns when high-risk infrastructure changes are detected.\n"
            "• Automated Access Revocation:\n"
            "  Trigger automated deprovisioning events to revoke stale or overprivileged entitlements on target connected sources.",
        ),
        (
            Inches(0.8),
            y_r2,
            "3. AWS Security Hub & EventBridge Webhooks",
            "Closed-Loop Cloud Threat Drift Remediation (Planned)",
            C_AWS,
            "• Cloud Drift Detection:\n"
            "  Ingest AWS EventBridge and CloudTrail event streams to detect manual out-of-band infrastructure changes that bypass Terraform.\n"
            "• Automated Quarantine Actions:\n"
            "  Trigger AWS Lambda security responders to detach overprivileged policies or restrict security groups when drift is detected.\n"
            "• Security Hub Synchronization:\n"
            "  Export SimuGuard AI blast radius findings as standardized ASFF findings directly into AWS Security Hub.",
        ),
        (
            Inches(6.78),
            y_r2,
            "4. Enterprise CI/CD PR Simulation Bot",
            "Automated Developer Pull Request Safety Gate (Planned)",
            C_WORKLOAD,
            "• GitHub Actions & GitLab CI Pipeline Integration:\n"
            "  Run SimuGuard AI analysis automatically on every pull request that touches Terraform HCL or firewall policy files.\n"
            "• In-Line Pull Request Feedback:\n"
            "  Post detailed Markdown comments on pull requests showing visual blast-radius diagrams, affected assets, and risk scores.\n"
            "• Automated Remediation Diffs:\n"
            "  Generate one-click remediated Terraform diffs implementing least-privilege configurations automatically.",
        ),
    ]

    for x, y, title, sub, col, text in quads:
        add_card(slide, x, y, card_w, card_h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_CARD_BG, border_color=col, title_color=col, title_size=10.5, sub_color=C_TEXT_DARK, sub_size=7.5)


# --- SLIDE 19: Architecture Summary & Key Takeaways (Dark Theme) ---
def build_slide_19():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_NAVY_DARK)
    add_header(slide, "Executive Synthesis & Enterprise Architectural Maturity", "Architecture Summary", 19, is_dark=True)

    card_w = Inches(5.74)
    card_h = Inches(2.4)
    y_r1 = Inches(1.35)
    y_r2 = Inches(3.95)

    quads = [
        (
            Inches(0.8),
            y_r1,
            "1. Robust Hybrid Foundation",
            "Defense-in-Depth Across Network & Cloud",
            C_FIREWALL,
            "• Dual-tier Palo Alto HA firewalls (PA-5450 Edge, PA-3440 Internal) and 9 security zones ensure no uninspected packet enters the enterprise.\n"
            "• Multi-account AWS architecture cleanly separates Production workloads, Development sandboxes, and Central Security audit vaults.\n"
            "• Micro-segmented enclaves isolate PCI cardholder data and CUI financial ledgers from general compute workloads.",
        ),
        (
            Inches(6.78),
            y_r1,
            "2. Modern Identity Governance",
            "Decoupled Governance Plane via SailPoint ISC",
            C_SAILPOINT,
            "• SailPoint ISC centralizes identity lifecycles across 8 connected sources, 22 identities, and 65 accounts.\n"
            "• Distinct separation of identity governance (who should have access) from runtime authorization (enforced by AWS IAM & PAN-OS).\n"
            "• Strict verification gates (PENDING_IS_NOT_ACCESS and PROVISIONING_GATE) prevent governance assumptions from becoming false security.",
        ),
        (
            Inches(0.8),
            y_r2,
            "3. Comprehensive Data Protection",
            "5 Classification Tiers & Envelope Encryption",
            C_DATA,
            "• All 6 core enterprise data assets are categorized into strict compliance tiers (NIST SP 800-171 CUI, PCI DSS, GDPR, SOX 404).\n"
            "• Customer-managed KMS keys enforce envelope encryption with automated rotation.\n"
            "• Dedicated Point-to-Point Transit and isolated database subnets prevent direct external reachability.",
        ),
        (
            Inches(6.78),
            y_r2,
            "4. Pre-Deployment Simulation",
            "Automated Digital Twin Change Safety",
            C_WORKLOAD,
            "• SimuGuard AI bridges infrastructure-as-code changes and runtime cybersecurity architecture.\n"
            "• Evaluates lateral blast radius across network, cloud, identity, and application dependencies before code is deployed.\n"
            "• Issues automated deployment verdicts (ALLOW, WARN_MANUAL_REVIEW, BLOCK_DEPLOYMENT) with actionable remediation recommendations.",
        ),
    ]

    for x, y, title, sub, col, text in quads:
        add_card(slide, x, y, card_w, card_h, title=title, subtitle=f"{sub}\n\n{text}", bg_color=C_SLATE_DARK, border_color=col, title_color=col, title_size=11, sub_color=RGBColor(226, 232, 240), sub_size=8)

    # Bottom Scorecard Banner
    add_card(
        slide,
        Inches(0.8),
        Inches(6.45),
        Inches(11.733),
        Inches(0.6),
        title="ENTERPRISE MATURITY SCORECARD: TIER-1 CYBERSECURITY & GOVERNANCE POSTURE",
        subtitle="Network Security: Tier 1 (PAN-OS 11.1) | Cloud Security: Tier 1 (AWS Multi-Account) | Identity Governance: Tier 1 (SailPoint ISC) | Change Safety: Pioneering (SimuGuard AI)",
        bg_color=RGBColor(15, 23, 42),
        border_color=C_TEXT_GOLD,
        title_color=C_TEXT_GOLD,
        title_size=9,
        sub_color=RGBColor(203, 213, 225),
        sub_size=7.5,
    )


# --- SLIDE 20: Glossary & Architecture Legend (Light Theme) ---
def build_slide_20():
    slide = prs.slides.add_slide(blank_layout)
    set_bg(slide, C_BG_LIGHT)
    add_header(slide, "Technical Terminology & Architecture Visual Taxonomy", "Glossary & Legend", 20)

    # Left: Technical Acronym Glossary Table
    glossary_headers = ["Acronym / Term", "Full Technical Name", "Architectural Role & Definition in Apex Global"]
    glossary_rows = [
        ["PAN-OS", "Palo Alto Networks OS", "Next-generation firewall operating system running version 11.1 Nebula"],
        ["App-ID", "Application Identification", "Layer 7 inspection engine classifying network traffic by true application payload"],
        ["Panorama", "Centralized Management Server", "M-600 Virtual appliance (pan-mgmt-01) managing firewall device groups & templates"],
        ["ISC", "Identity Security Cloud", "SailPoint central cloud Identity Governance and Administration (IGA) tenant"],
        ["IRSA", "IAM Roles for Service Accounts", "EKS OIDC pod federation binding Kubernetes service accounts to AWS IAM roles"],
        ["CUI", "Controlled Unclassified Information", "NIST SP 800-171 regulated corporate financial ledgers and treasury reserves"],
        ["PCI DSS", "Payment Card Industry Standard", "Security standard enforcing strict enclave isolation for credit card tokenization"],
        ["RBAC / ABAC", "Role / Attribute-Based Access", "SailPoint three-tier access model (Role -> Access Profile -> Entitlement)"],
        ["SoD", "Separation of Duties", "Governance policy preventing toxic combinations of conflicting administrative access"],
        ["Digital Twin", "Graph Infrastructure Model", "NetworkX directed graph modeling 220 assets and 77 dependencies in SimuGuard AI"],
        ["Blast Radius", "Infrastructure Impact Propagation", "Direct and cascading assets affected by proposed infrastructure changes"],
    ]
    col_w_g = [Inches(1.5), Inches(2.2), Inches(2.7)]
    add_table_grid(slide, Inches(0.8), Inches(1.35), Inches(6.4), Inches(5.6), glossary_headers, glossary_rows, col_w_g, header_bg=C_NAVY_DARK)

    # Right: Architecture Visual Legend Cards
    add_card(
        slide,
        Inches(7.4),
        Inches(1.35),
        Inches(5.133),
        Inches(5.6),
        title="ARCHITECTURE VISUAL TAXONOMY & LEGEND",
        subtitle=(
            "Color Palette Taxonomy:\n"
            "• Red (#DC2626): Perimeter & Internal Firewalls (PA-5450 / PA-3440)\n"
            "• Purple (#7C3AED): Panorama Central Management Server (pan-mgmt-01)\n"
            "• Blue (#0284C7): AWS Cloud Infrastructure & Production Account\n"
            "• Indigo (#4F46E5): SailPoint Identity Security Cloud Governance Plane\n"
            "• Green (#059669): Production Kubernetes Compute Workloads & EKS Clusters\n"
            "• Amber (#D97706): Classified Data Assets & Sensitive CUI Storage Repositories\n"
            "• Cyan (#0891B2): Development Account & Ephemeral Sandbox Workloads\n"
            "• Pink (#DB2777): Central Security Operations Account & SIEM Forwarder\n\n"
            "Relationship Line Styles:\n"
            "• Solid Line: Active, configured infrastructure dependency (e.g., HOSTS_APPLICATION)\n"
            "• Dashed Line: Management or governance relationship (e.g., GOVERNED_BY_SAILPOINT)\n"
            "• Bold Double Line: Primary network data transit / point-to-point interconnect\n\n"
            "SimuGuard AI Verdict Badges:\n"
            "• ALLOW (Green): Pre-flight check passed; no least-privilege or blast violations.\n"
            "• WARN_MANUAL_REVIEW (Amber): Elevated blast radius or unmapped resources detected.\n"
            "• BLOCK_DEPLOYMENT (Red): Critical vulnerability (App-ID bypass, S3 wildcard) blocked."
        ),
        bg_color=C_CARD_BG,
        border_color=C_SAILPOINT,
        title_color=C_SAILPOINT,
        title_size=10.5,
        sub_size=7.5,
    )


# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
def main():
    print("Building Slide 01: Cover Page...")
    build_slide_01()
    print("Building Slide 02: Executive Summary...")
    build_slide_02()
    print("Building Slide 03: Technology Overview...")
    build_slide_03()
    print("Building Slide 04: Complete Enterprise Architecture...")
    build_slide_04()
    print("Building Slide 05: Network Topology...")
    build_slide_05()
    print("Building Slide 06: Firewall Architecture...")
    build_slide_06()
    print("Building Slide 07: Panorama Architecture...")
    build_slide_07()
    print("Building Slide 08: Security Zones...")
    build_slide_08()
    print("Building Slide 09: AWS Multi-Account...")
    build_slide_09()
    print("Building Slide 10: AWS Infrastructure...")
    build_slide_10()
    print("Building Slide 11: SailPoint Architecture...")
    build_slide_11()
    print("Building Slide 12: Identity Lifecycle & RBAC...")
    build_slide_12()
    print("Building Slide 13: Application Architecture...")
    build_slide_13()
    print("Building Slide 14: Data Architecture...")
    build_slide_14()
    print("Building Slide 15: Dependency Architecture...")
    build_slide_15()
    print("Building Slide 16: Security Boundaries...")
    build_slide_16()
    print("Building Slide 17: SimuGuard AI Platform...")
    build_slide_17()
    print("Building Slide 18: Future Roadmap...")
    build_slide_18()
    print("Building Slide 19: Architecture Summary...")
    build_slide_19()
    print("Building Slide 20: Glossary & Legend...")
    build_slide_20()

    print(f"Saving presentation to: {PPTX_PATH}")
    prs.save(str(PPTX_PATH))
    print(f"Presentation saved successfully. Slide count: {len(prs.slides)}")


if __name__ == "__main__":
    main()

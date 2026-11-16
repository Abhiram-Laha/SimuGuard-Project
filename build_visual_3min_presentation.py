import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_presentation(output_path):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Theme Colors
    BG_DARK = RGBColor(11, 19, 43)        # #0B132B Deep Navy
    BG_CARD = RGBColor(21, 34, 56)        # #152238 Dark Slate
    BG_CARD_ALT = RGBColor(15, 26, 46)    # #0F1A2E Alternate Card
    BORDER_DEFAULT = RGBColor(30, 58, 138) # #1E3A8A Blue Border
    BORDER_CYAN = RGBColor(2, 132, 199)    # #0284C7 Electric Cyan
    BORDER_RED = RGBColor(239, 68, 68)     # #EF4444 Alert Red
    BORDER_GREEN = RGBColor(16, 185, 129)  # #10B981 Safe Green
    BORDER_AMBER = RGBColor(245, 158, 11)  # #F59E0B Warning Amber
    
    TEXT_WHITE = RGBColor(255, 255, 255)
    TEXT_CYAN = RGBColor(56, 189, 248)    # #38BDF8
    TEXT_SILVER = RGBColor(203, 213, 225) # #CBD5E1
    TEXT_MUTED = RGBColor(148, 163, 184)  # #94A3B8
    TEXT_GREEN = RGBColor(52, 211, 153)   # #34D399
    TEXT_RED = RGBColor(248, 113, 113)    # #F87171

    def apply_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.fill.background()
        return bg

    def add_header(slide, tag, title, subtitle):
        # Tag
        tb_tag = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(0.3))
        p = tb_tag.text_frame.paragraphs[0]
        p.text = tag.upper()
        p.font.name = 'Arial'
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = TEXT_CYAN

        # Title
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.65), Inches(11.733), Inches(0.6))
        p = tb_title.text_frame.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(24)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE

        # Subtitle
        tb_sub = slide.shapes.add_textbox(Inches(0.8), Inches(1.22), Inches(11.733), Inches(0.35))
        p = tb_sub.text_frame.paragraphs[0]
        p.text = subtitle
        p.font.name = 'Arial'
        p.font.size = Pt(11.5)
        p.font.color.rgb = TEXT_SILVER

        # Top divider line
        line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.6), Inches(11.733), Pt(1.5))
        line.fill.solid()
        line.fill.fore_color.rgb = BORDER_CYAN
        line.line.fill.background()

    def add_card(slide, x, y, w, h, bg_color=BG_CARD, border_color=BORDER_DEFAULT, border_pt=1):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        if border_color:
            card.line.color.rgb = border_color
            card.line.width = Pt(border_pt)
        else:
            card.line.fill.background()
        return card

    def add_arrow(slide, x, y, w, h, color=TEXT_CYAN):
        arrow = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x), Inches(y), Inches(w), Inches(h))
        arrow.fill.solid()
        arrow.fill.fore_color.rgb = color
        arrow.line.fill.background()
        return arrow

    def set_notes(slide, notes_text):
        notes_slide = slide.notes_slide
        tf = notes_slide.notes_text_frame
        tf.text = notes_text

    # =========================================================================
    # SLIDE 1: INTRODUCING SIMUGUARD AI
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    apply_bg(s1)

    # Top Brand Header
    tb = s1.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.733), Inches(1.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p0 = tf.paragraphs[0]
    p0.text = "SIMUGUARD AI"
    p0.font.name = 'Arial'
    p0.font.size = Pt(36)
    p0.font.bold = True
    p0.font.color.rgb = TEXT_WHITE
    p0.alignment = PP_ALIGN.CENTER

    p1 = tf.add_paragraph()
    p1.text = "AI-Powered Security Change Risk Assessment"
    p1.font.name = 'Arial'
    p1.font.size = Pt(16)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_CYAN
    p1.alignment = PP_ALIGN.CENTER

    # Main Visual: 3-Stage Pre-Flight Concept
    # Box 1: Proposed IT Change
    c1 = add_card(s1, 0.8, 1.9, 3.2, 2.9, BG_CARD, BORDER_DEFAULT, 1.5)
    tf1 = c1.text_frame
    tf1.word_wrap = True
    tf1.vertical_anchor = MSO_ANCHOR.TOP
    p = tf1.paragraphs[0]
    p.text = "PROPOSED IT CHANGE\n"
    p.font.name = 'Arial'
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    items1 = [
        ("• Firewall Rule Changes", TEXT_CYAN),
        ("  (e.g., Allow Analytics Outbound)", TEXT_SILVER),
        ("• Cloud IAM Policies", TEXT_CYAN),
        ("  (e.g., AdministratorAccess, S3)", TEXT_SILVER),
        ("• Identity Lifecycle Shifts", TEXT_CYAN),
        ("  (Joiner, Mover, Leaver events)", TEXT_SILVER),
    ]
    for text, col in items1:
        pi = tf1.add_paragraph()
        pi.text = text
        pi.font.name = 'Arial'
        pi.font.size = Pt(9.5)
        pi.font.color.rgb = col

    # Arrow 1 ->
    add_arrow(s1, 4.2, 3.1, 0.6, 0.4, BORDER_CYAN)

    # Box 2: Center Shield / Engine
    c2 = add_card(s1, 5.0, 1.9, 3.5, 2.9, RGBColor(16, 37, 66), BORDER_CYAN, 2)
    tf2 = c2.text_frame
    tf2.word_wrap = True
    tf2.vertical_anchor = MSO_ANCHOR.TOP
    p = tf2.paragraphs[0]
    p.text = "SIMUGUARD AI\nSIMULATION ENGINE"
    p.font.name = 'Arial'
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_CYAN
    p.alignment = PP_ALIGN.CENTER

    items2 = [
        ("1. In-Memory Digital Twin", TEXT_WHITE),
        ("   Replicates network & cloud graph", TEXT_SILVER),
        ("2. Blast-Radius Traversal", TEXT_WHITE),
        ("   Multi-hop path reachability check", TEXT_SILVER),
        ("3. Deterministic Risk Engine", TEXT_WHITE),
        ("   Scores severity from 0 to 100", TEXT_SILVER),
    ]
    for text, col in items2:
        pi = tf2.add_paragraph()
        pi.text = text
        pi.font.name = 'Arial'
        pi.font.size = Pt(9.5)
        pi.font.color.rgb = col

    # Arrow 2 ->
    add_arrow(s1, 8.7, 3.1, 0.6, 0.4, BORDER_CYAN)

    # Box 3: Safe / Risky Results
    # 3A: Safe
    c3a = add_card(s1, 9.5, 1.9, 3.0, 1.35, BG_CARD, BORDER_GREEN, 1.5)
    tf3a = c3a.text_frame
    tf3a.word_wrap = True
    p = tf3a.paragraphs[0]
    p.text = "SAFE OUTCOME"
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_GREEN
    p.alignment = PP_ALIGN.CENTER
    p = tf3a.add_paragraph()
    p.text = "ALLOW (0-39 Score)\nApproved for production deployment without security blind spots."
    p.font.size = Pt(8.5)
    p.font.color.rgb = TEXT_SILVER

    # 3B: Risky
    c3b = add_card(s1, 9.5, 3.45, 3.0, 1.35, BG_CARD, BORDER_RED, 1.5)
    tf3b = c3b.text_frame
    tf3b.word_wrap = True
    p = tf3b.paragraphs[0]
    p.text = "SECURITY RISK DETECTED"
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_RED
    p.alignment = PP_ALIGN.CENTER
    p = tf3b.add_paragraph()
    p.text = "BLOCK / WARN (40-100)\nFlags toxic paths & synthesizes a safe candidate configuration."
    p.font.size = Pt(8.5)
    p.font.color.rgb = TEXT_SILVER

    # Tagline Banner
    banner = add_card(s1, 0.8, 5.05, 11.733, 0.65, RGBColor(2, 60, 105), BORDER_CYAN, 1.5)
    tb_b = s1.shapes.add_textbox(Inches(0.8), Inches(5.05), Inches(11.733), Inches(0.65))
    p = tb_b.text_frame.paragraphs[0]
    p.text = "Check security changes before they reach production."
    p.font.name = 'Arial'
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    # Presenter Information Row
    p_box = s1.shapes.add_textbox(Inches(0.8), Inches(5.95), Inches(11.733), Inches(0.9))
    tf_p = p_box.text_frame
    tf_p.word_wrap = True
    p_pres = tf_p.paragraphs[0]
    p_pres.text = "PRESENTERS:"
    p_pres.font.name = 'Arial'
    p_pres.font.size = Pt(10)
    p_pres.font.bold = True
    p_pres.font.color.rgb = TEXT_CYAN
    p_pres.alignment = PP_ALIGN.CENTER

    p_names = tf_p.add_paragraph()
    p_names.text = "Ameya Shree Kasa — Security Engineer I    |    Abhiram Laha — Managed Service Engineer I"
    p_names.font.name = 'Arial'
    p_names.font.size = Pt(12)
    p_names.font.bold = True
    p_names.font.color.rgb = TEXT_WHITE
    p_names.alignment = PP_ALIGN.CENTER

    p_sub = tf_p.add_paragraph()
    p_sub.text = "3-Minute Live Judge Presentation  •  Apex Global Technologies Security Testbed"
    p_sub.font.name = 'Arial'
    p_sub.font.size = Pt(9.5)
    p_sub.font.color.rgb = TEXT_MUTED
    p_sub.alignment = PP_ALIGN.CENTER

    set_notes(s1, 
        "SPEAKER: Ameya Shree Kasa (0:00 - 0:15 | 15s)\n\n"
        "[CLICK SLIDE 1]\n"
        "\"Good morning, judges. I am Ameya Shree Kasa, Security Engineer I, and with me is Abhiram Laha, Managed Service Engineer I. "
        "Today, we are presenting SimuGuard AI: an intelligent pre-deployment simulation engine that checks enterprise firewall and cloud security changes "
        "before they reach production.\""
    )

    # =========================================================================
    # SLIDE 2: THE PROBLEM
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    apply_bg(s2)
    add_header(s2, "The Enterprise Problem", "One Small Change Can Create a Big Security Risk", 
               "Routine IT changes frequently introduce unintended vulnerabilities that peer reviews miss.")

    # Main Visual: 3-Stage Attack/Exposure Chain
    # Box 1: Engineer Requests Access
    c_p1 = add_card(s2, 0.8, 1.9, 3.5, 2.5, BG_CARD, BORDER_DEFAULT, 1)
    tf = c_p1.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "1. ACCESS REQUESTED"
    p.font.name = 'Arial'
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER
    items = [
        ("• Engineer opens change ticket", TEXT_CYAN),
        ("• Needs external connectivity", TEXT_SILVER),
        ("• Goal: download packages or integrate third-party APIs", TEXT_MUTED)
    ]
    for t, c in items:
        pi = tf.add_paragraph()
        pi.text = t
        pi.font.size = Pt(9)
        pi.font.color.rgb = c

    add_arrow(s2, 4.45, 2.9, 0.5, 0.35, BORDER_AMBER)

    # Box 2: Broad Access Mistake Introduced
    c_p2 = add_card(s2, 5.1, 1.9, 3.5, 2.5, RGBColor(38, 20, 20), BORDER_RED, 2)
    tf = c_p2.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "2. MISTAKE INTRODUCED"
    p.font.name = 'Arial'
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_RED
    p.alignment = PP_ALIGN.CENTER
    items = [
        ("• Wildcard rule applied: 'any'", TEXT_RED),
        ("• Destination: ANY internet host", TEXT_SILVER),
        ("• App-ID & security inspection left disabled to 'prevent issues'", TEXT_MUTED)
    ]
    for t, c in items:
        pi = tf.add_paragraph()
        pi.text = t
        pi.font.size = Pt(9)
        pi.font.color.rgb = c

    add_arrow(s2, 8.75, 2.9, 0.5, 0.35, BORDER_RED)

    # Box 3: Sensitive Database at Risk
    c_p3 = add_card(s2, 9.4, 1.9, 3.133, 2.5, RGBColor(50, 15, 15), BORDER_RED, 2)
    tf = c_p3.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "3. ASSETS AT RISK"
    p.font.name = 'Arial'
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_RED
    p.alignment = PP_ALIGN.CENTER
    items = [
        ("• Internal servers exposed", TEXT_RED),
        ("• Sensitive database reachable", TEXT_SILVER),
        ("• Downstream path created for data exfiltration or breach", TEXT_MUTED)
    ]
    for t, c in items:
        pi = tf.add_paragraph()
        pi.text = t
        pi.font.size = Pt(9)
        pi.font.color.rgb = c

    # Concrete visual example banner
    ex_card = add_card(s2, 0.8, 4.6, 11.733, 0.55, BG_CARD_ALT, BORDER_AMBER, 1)
    tb_ex = s2.shapes.add_textbox(Inches(0.8), Inches(4.6), Inches(11.733), Inches(0.55))
    p = tb_ex.text_frame.paragraphs[0]
    p.text = "EXPOSURE CHAIN:  Engineer  →  Broad Access Rule ('ANY' Destination)  →  Sensitive Systems & Data at Risk"
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    # 3 Supporting Points (as requested by user)
    pts = [
        ("CONFIGURATION MISTAKES", "Simple misconfigurations create unintended security gaps in firewalls and cloud permissions.", BORDER_CYAN),
        ("MANUAL REVIEW BLIND SPOTS", "Peer reviewers look at single tickets in isolation and miss indirect, multi-hop dependencies.", BORDER_AMBER),
        ("HARDER TO FIX AFTER", "Once deployed, identifying and rolling back a dangerous change is disruptive and costly.", BORDER_RED)
    ]
    for idx, (title, desc, b_col) in enumerate(pts):
        xp = 0.8 + idx * 4.0
        cp = add_card(s2, xp, 5.35, 3.733, 1.6, BG_CARD, b_col, 1)
        tf_pt = cp.text_frame
        tf_pt.word_wrap = True
        p = tf_pt.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE
        p.alignment = PP_ALIGN.CENTER
        p = tf_pt.add_paragraph()
        p.text = desc
        p.font.size = Pt(9)
        p.font.color.rgb = TEXT_SILVER
        p.alignment = PP_ALIGN.CENTER

    set_notes(s2,
        "SPEAKER: Ameya Shree Kasa (0:15 - 0:40 | 25s)\n\n"
        "[CLICK SLIDE 2]\n"
        "\"Every day, enterprise teams approve firewall and cloud permission changes. But security gaps often start with routine changes. "
        "An engineer requests connectivity for a routine task, but to avoid troubleshooting, an over-permissive rule like 'destination ANY' or administrator privileges is requested. "
        "Manual peer reviews inspect tickets in isolation and miss indirect, multi-hop dependencies. By the time a problem is detected in production, sensitive databases are already exposed.\""
    )

    # =========================================================================
    # SLIDE 3: OUR SOLUTION
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    apply_bg(s3)
    add_header(s3, "The Solution", "Simulate First. Approve Safely.", 
               "Evaluate the complete ripple effect in a virtual Digital Twin before applying any change.")

    # Large Horizontal Workflow (5 Steps)
    wf_steps = [
        ("1. CHANGE REQUEST", "ServiceNow ticket or configuration", BORDER_CYAN),
        ("2. SIMUGUARD AI", "Extracts & validates attributes", BORDER_CYAN),
        ("3. DIGITAL TWIN", "Simulates change in virtual graph", BORDER_CYAN),
        ("4. RISK ANALYSIS", "Evaluates multi-hop blast radius", BORDER_AMBER),
        ("5. DECISION", "ALLOW | WARN | BLOCK", BORDER_GREEN),
    ]

    for idx, (title, sub, bcol) in enumerate(wf_steps):
        xp = 0.8 + idx * 2.45
        c_step = add_card(s3, xp, 1.85, 2.05, 1.35, BG_CARD, bcol, 1.5)
        tf = c_step.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE
        p.alignment = PP_ALIGN.CENTER
        p = tf.add_paragraph()
        p.text = sub
        p.font.size = Pt(8)
        p.font.color.rgb = TEXT_SILVER
        p.alignment = PP_ALIGN.CENTER

        if idx < 4:
            add_arrow(s3, xp + 2.1, 2.35, 0.3, 0.25, TEXT_CYAN)

    # Digital Twin Definition Callout (User requested plain-language definition)
    dt_box = add_card(s3, 0.8, 3.4, 11.733, 0.85, RGBColor(16, 37, 66), BORDER_CYAN, 1.5)
    tf_dt = dt_box.text_frame
    tf_dt.word_wrap = True
    p = tf_dt.paragraphs[0]
    p.text = "WHAT IS THE DIGITAL TWIN?"
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_CYAN
    p.alignment = PP_ALIGN.CENTER

    p = tf_dt.add_paragraph()
    p.text = "“A virtual model of the organization's infrastructure used to test proposed changes without changing the live environment.”"
    p.font.name = 'Arial'
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    # Comparison: WITHOUT vs WITH SIMUGUARD
    # Without Card
    c_wo = add_card(s3, 0.8, 4.45, 5.7, 1.9, RGBColor(38, 20, 20), BORDER_RED, 1.5)
    tf = c_wo.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "WITHOUT SIMUGUARD (REACTIVE)"
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_RED
    p.alignment = PP_ALIGN.CENTER

    items_wo = [
        "Request  →  Manual Review  →  Deploy  →  Risk Found Later",
        "• Peer reviewers guess the impact without seeing dependencies.",
        "• Security holes and outages are only discovered after deployment.",
        "• High risk of emergency rollbacks and data exposure."
    ]
    for it in items_wo:
        pi = tf.add_paragraph()
        pi.text = it
        pi.font.size = Pt(8.5)
        pi.font.color.rgb = TEXT_SILVER

    # With Card
    c_w = add_card(s3, 6.833, 4.45, 5.7, 1.9, RGBColor(16, 45, 35), BORDER_GREEN, 1.5)
    tf = c_w.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "WITH SIMUGUARD AI (PROACTIVE)"
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_GREEN
    p.alignment = PP_ALIGN.CENTER

    items_w = [
        "Request  →  Simulation  →  Risk Identified  →  Recommendation Before Deploy",
        "• Tests the proposed change in a virtual replica of the network.",
        "• Flags toxic paths and security policy violations in seconds.",
        "• Recommends a safer candidate configuration before anything goes live."
    ]
    for it in items_w:
        pi = tf.add_paragraph()
        pi.text = it
        pi.font.size = Pt(8.5)
        pi.font.color.rgb = TEXT_SILVER

    # Handover Callout
    ho_tb = s3.shapes.add_textbox(Inches(0.8), Inches(6.5), Inches(11.733), Inches(0.45))
    p = ho_tb.text_frame.paragraphs[0]
    p.text = "Handover to Abhiram: “Now, Abhiram will explain how this works technically and show a practical example.”"
    p.font.name = 'Arial'
    p.font.size = Pt(10.5)
    p.font.bold = True
    p.font.color.rgb = TEXT_CYAN
    p.alignment = PP_ALIGN.CENTER

    set_notes(s3,
        "SPEAKER: Ameya Shree Kasa (0:40 - 1:05 | 25s)\n\n"
        "[CLICK SLIDE 3]\n"
        "\"SimuGuard AI solves this by simulating the change first. Before anything touches production, we load the request into an in-memory Digital Twin—"
        "a virtual model of the enterprise network and cloud permissions. "
        "Without SimuGuard, changes are deployed blindly and risks are discovered during outages. "
        "With SimuGuard, we identify the exact blast radius and recommend a safer candidate before deployment. "
        "Now, Abhiram will explain how this works technically and show a practical example.\""
    )

    # =========================================================================
    # SLIDE 4: HOW IT ACTUALLY WORKS (ARCHITECTURE)
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    apply_bg(s4)
    add_header(s4, "Technical Architecture", "Inside SimuGuard AI: From Request to Risk Decision", 
               "A clean six-stage pipeline that validates, simulates, and scores change requests in memory.")

    # 6 Large Connected Stages in a 2x3 Grid
    # Row 1 (Stages 1, 2, 3)
    stages_r1 = [
        ("1. CHANGE REQUEST", "Engineer pastes change ticket\n• Free text or structured input\n• ServiceNow change format", BORDER_CYAN),
        ("2. REQUEST PARSER", "Extracts & validates attributes\n• Regex pattern extraction\n• Pydantic schema validation", BORDER_CYAN),
        ("3. DIGITAL TWIN", "In-memory enterprise graph\n• NetworkX graph representation\n• 220 nodes & 77 relationships", BORDER_CYAN),
    ]

    for idx, (title, desc, bcol) in enumerate(stages_r1):
        xp = 0.8 + idx * 4.05
        c_st = add_card(s4, xp, 1.85, 3.4, 1.8, BG_CARD, bcol, 1.5)
        tf = c_st.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE
        p.alignment = PP_ALIGN.CENTER
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(8.5)
        p.font.color.rgb = TEXT_SILVER
        
        if idx < 2:
            add_arrow(s4, xp + 3.48, 2.55, 0.45, 0.3, TEXT_CYAN)

    # Arrow from Stage 3 down to Stage 4 (or visual connector)
    # Row 2 (Stages 4, 5, 6)
    stages_r2 = [
        ("4. SECURITY ANALYSIS", "Dual-domain rule verification\n• Palo Alto firewall rule checks\n• Cloud IAM & identity analysis", BORDER_AMBER),
        ("5. RISK ENGINE", "Quantitative risk calculation\n• Asset criticality & blast radius\n• Deterministic 0 to 100 score", BORDER_AMBER),
        ("6. DECISION & REPORT", "Actionable recommendations\n• ALLOW / WARN / BLOCK\n• Safer candidate configuration", BORDER_GREEN),
    ]

    for idx, (title, desc, bcol) in enumerate(stages_r2):
        xp = 0.8 + idx * 4.05
        c_st = add_card(s4, xp, 3.9, 3.4, 1.8, BG_CARD, bcol, 1.5)
        tf = c_st.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE
        p.alignment = PP_ALIGN.CENTER
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(8.5)
        p.font.color.rgb = TEXT_SILVER

        if idx < 2:
            add_arrow(s4, xp + 3.48, 4.6, 0.45, 0.3, TEXT_CYAN)

    # Down arrow connecting Stage 3 to Stage 6 or 4 to show flow
    down_arr = s4.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(10.5), Inches(3.68), Inches(0.4), Inches(0.2))
    down_arr.fill.solid()
    down_arr.fill.fore_color.rgb = BORDER_CYAN
    down_arr.line.fill.background()

    # Compact Technology Strip Below (as requested by user)
    tech_banner = add_card(s4, 0.8, 5.95, 11.733, 0.95, RGBColor(16, 28, 48), BORDER_CYAN, 1)
    tf_tech = tech_banner.text_frame
    tf_tech.word_wrap = True
    p = tf_tech.paragraphs[0]
    p.text = "CORE IMPLEMENTATION STACK:"
    p.font.name = 'Arial'
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = TEXT_CYAN
    p.alignment = PP_ALIGN.CENTER

    tech_items = [
        "Python (Core logic & algorithms)  •  Streamlit (Interactive UI)  •  NetworkX (In-memory graph traversals)",
        "Pydantic (Strict schema validation)  •  SQLite (Audit logging & assessment history)"
    ]
    for ti in tech_items:
        pi = tf_tech.add_paragraph()
        pi.text = ti
        pi.font.size = Pt(9)
        pi.font.color.rgb = TEXT_WHITE
        pi.alignment = PP_ALIGN.CENTER

    set_notes(s4,
        "SPEAKER: Abhiram Laha (1:05 - 1:50 | 45s)\n\n"
        "[CLICK SLIDE 4]\n"
        "\"Thank you, Ameya. Under the hood, SimuGuard AI operates as a six-stage in-memory simulation pipeline. "
        "First, when an engineer submits a change ticket, our parser extracts the parameters and validates them using Pydantic. "
        "Next, we clone our Digital Twin—an in-memory NetworkX graph representing the organization with 220 nodes and 77 directional relationships. "
        "Our security engine evaluates both network firewall rules and cloud IAM permissions, while the risk engine traverses multi-hop reachability paths to produce an explainable 0 to 100 risk score. "
        "Everything runs locally in Python and Streamlit, with every simulation recorded to a local SQLite audit ledger.\""
    )

    # =========================================================================
    # SLIDE 5: PRACTICAL EXAMPLE (CHG-2026-1002)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    apply_bg(s5)
    add_header(s5, "Practical Verification", "A Realistic Enterprise Scenario: Unrestricted Internet Access", 
               "Synthetic demonstration scenario CHG-2026-1002 evaluated against Apex Global Technologies.")

    # Side-by-Side Comparison
    # Left Card: Proposed Change / Risk
    c_left = add_card(s5, 0.8, 1.85, 5.7, 4.4, RGBColor(38, 18, 18), BORDER_RED, 2)
    tf_l = c_left.text_frame
    tf_l.word_wrap = True
    
    p = tf_l.paragraphs[0]
    p.text = "PROPOSED CHANGE (HIGH RISK)"
    p.font.name = 'Arial'
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_RED
    p.alignment = PP_ALIGN.CENTER

    items_l = [
        ("Change Request: CHG-2026-1002", TEXT_WHITE),
        ("Source: Analytics Servers (10.100.20.0/24)", TEXT_SILVER),
        ("Destination Address: ANY (Wildcard)", TEXT_RED),
        ("Application / App-ID: ANY (Unrestricted)", TEXT_RED),
        ("Service / Port: ANY | Action: Allow", TEXT_RED),
        ("Security Inspection Profile: NONE", TEXT_RED),
        ("Audit Logging: DISABLED", TEXT_RED),
        ("", TEXT_WHITE),
        ("DETECTED RISK FINDINGS:", TEXT_AMBER if 'TEXT_AMBER' in locals() else TEXT_CYAN),
        ("• Wildcard destination allows connection to any external server", TEXT_SILVER),
        ("• App-ID bypass allows arbitrary protocol tunneling", TEXT_SILVER),
        ("• Zero threat inspection allows malware or data exfiltration", TEXT_SILVER),
        ("", TEXT_WHITE),
        ("SIMULATION VERDICT:  BLOCK DEPLOYMENT", TEXT_RED),
        ("COMPOSITE RISK SCORE:  100 / 100 (HIGH RISK)", TEXT_RED),
    ]
    for t, c in items_l:
        pi = tf_l.add_paragraph()
        pi.text = t
        pi.font.size = Pt(8.5)
        pi.font.color.rgb = c
        if "VERDICT:" in t or "SCORE:" in t:
            pi.font.bold = True
            pi.font.size = Pt(10)
            pi.alignment = PP_ALIGN.CENTER

    # Right Card: Recommended Candidate Change
    c_right = add_card(s5, 6.833, 1.85, 5.7, 4.4, RGBColor(16, 42, 32), BORDER_GREEN, 2)
    tf_r = c_right.text_frame
    tf_r.word_wrap = True
    
    p = tf_r.paragraphs[0]
    p.text = "RECOMMENDED CANDIDATE (SAFE SIMULATION)"
    p.font.name = 'Arial'
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_GREEN
    p.alignment = PP_ALIGN.CENTER

    items_r = [
        ("Simulated Candidate Configuration", TEXT_WHITE),
        ("Source: Analytics Servers (10.100.20.0/24)", TEXT_SILVER),
        ("Destination Address: Scoped Cloud/SaaS Mirrors", TEXT_GREEN),
        ("Application / App-ID: SSL / HTTPS Enforced", TEXT_GREEN),
        ("Service / Port: TCP-443 Only", TEXT_GREEN),
        ("Security Profile: Strict-Enterprise-Security", TEXT_GREEN),
        ("Audit Logging: ENABLED with alerts", TEXT_GREEN),
        ("", TEXT_WHITE),
        ("CANDIDATE SIMULATION RESULTS:", TEXT_CYAN),
        ("• Scoped destination limits access strictly to verified services", TEXT_SILVER),
        ("• Palo Alto App-ID enforces legitimate SSL/HTTPS traffic", TEXT_SILVER),
        ("• Full threat inspection (antivirus, anti-spyware, IPS) active", TEXT_SILVER),
        ("", TEXT_WHITE),
        ("CANDIDATE VERDICT:  VERIFIED SAFE / ALLOW", TEXT_GREEN),
        ("POST-REMEDIATION RISK SCORE:  0 / 100 (LOW RISK)", TEXT_GREEN),
    ]
    for t, c in items_r:
        pi = tf_r.add_paragraph()
        pi.text = t
        pi.font.size = Pt(8.5)
        pi.font.color.rgb = c
        if "VERDICT:" in t or "SCORE:" in t:
            pi.font.bold = True
            pi.font.size = Pt(10)
            pi.alignment = PP_ALIGN.CENTER

    # Bottom Banner (User requested exact text)
    bot_card = add_card(s5, 0.8, 6.4, 11.733, 0.55, RGBColor(16, 30, 52), BORDER_CYAN, 1)
    tb_b = s5.shapes.add_textbox(Inches(0.8), Inches(6.4), Inches(11.733), Inches(0.55))
    p = tb_b.text_frame.paragraphs[0]
    p.text = "SimuGuard AI identifies the risk and evaluates a safer candidate configuration before deployment."
    p.font.name = 'Arial'
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    set_notes(s5,
        "SPEAKER: Abhiram Laha (1:50 - 2:25 | 35s)\n\n"
        "[CLICK SLIDE 5]\n"
        "\"To see this in action, look at test scenario CHG-2026-1002 from our synthetic Apex Global dataset. "
        "An analytics team requested outbound internet access, but asked for wildcard ANY destination, ANY application, and disabled security inspection. "
        "SimuGuard AI immediately flagged the App-ID bypass and uninspected egress, computed a maximum risk score of 100 out of 100, and issued an automatic BLOCK recommendation. "
        "More importantly, our engine evaluated a safer candidate configuration—restricting traffic strictly to approved SaaS endpoints on port 443 with full threat inspection—dropping the simulated risk score to zero before deployment.\""
    )

    # =========================================================================
    # SLIDE 6: WHY IT MATTERS & PROJECT SCOPE
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    apply_bg(s6)
    add_header(s6, "Practical Value & Scope", "Safer Changes. Better Visibility.", 
               "Core business value backed by an honest understanding of prototype boundaries.")

    # 4 Large Visual Cards (2x2 Grid)
    cards_data = [
        ("EARLY RISK DETECTION", 
         "• Intercepts misconfigurations before they reach production.\n• Prevents high-severity outages and compliance violations.\n• Stops toxic permissions at the change request stage.",
         BORDER_CYAN),
        ("BLAST-RADIUS VISIBILITY", 
         "• Multi-hop graph reachability maps downstream ripple effects.\n• Identifies which databases, servers, and vaults are touched.\n• Eliminates peer review guesswork.",
         BORDER_CYAN),
        ("FIREWALL + CLOUD IAM", 
         "• Bridges network firewalls (Palo Alto) and cloud IAM in one view.\n• Detects toxic combinations across network and identity layers.\n• Covers joiner, mover, and leaver lifecycle workflows.",
         BORDER_CYAN),
        ("SAFER RECOMMENDATIONS", 
         "• Synthesizes least-privilege candidate configurations automatically.\n• Replaces wildcard rules with verified scoped endpoints.\n• Validates candidate safety before deployment.",
         BORDER_GREEN),
    ]

    for idx, (title, desc, bcol) in enumerate(cards_data):
        rx = 0.8 + (idx % 2) * 6.0
        ry = 1.85 + (idx // 2) * 1.95
        card = add_card(s6, rx, ry, 5.733, 1.75, BG_CARD, bcol, 1.5)
        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(8.5)
        p.font.color.rgb = TEXT_SILVER

    # Prototype Boundary Panel (User requested clearly visible boundary panel)
    bound_card = add_card(s6, 0.8, 5.9, 11.733, 0.95, RGBColor(28, 32, 45), BORDER_AMBER, 1.5)
    tf_b = bound_card.text_frame
    tf_b.word_wrap = True
    p = tf_b.paragraphs[0]
    p.text = "PROTOTYPE SCOPE & REALISTIC BOUNDARIES:"
    p.font.name = 'Arial'
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = TEXT_AMBER if 'TEXT_AMBER' in locals() else TEXT_CYAN

    p = tf_b.add_paragraph()
    p.text = "Current version: Local simulation prototype using synthetic enterprise data. It evaluates proposed changes in an in-memory testbed and does not directly modify live production firewalls or cloud accounts."
    p.font.name = 'Arial'
    p.font.size = Pt(9)
    p.font.color.rgb = TEXT_SILVER

    set_notes(s6,
        "SPEAKER: Abhiram Laha (2:25 - 2:45 | 20s)\n\n"
        "[CLICK SLIDE 6]\n"
        "\"The real value of SimuGuard AI is shifting security from reactive incident response to proactive pre-deployment simulation. "
        "It provides blast-radius visibility, unites network firewalls and cloud IAM into a single graph, and suggests safer candidate rules. "
        "To be completely transparent, our current version is a local simulation prototype evaluated on synthetic enterprise data—it tests changes safely in memory, without directly modifying live production firewalls.\""
    )

    # =========================================================================
    # SLIDE 7: STRONG CLOSING
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    apply_bg(s7)
    add_header(s7, "Conclusion", "Security Should Be Tested Before Deployment", 
               "Moving enterprise security review from reactive detection to proactive prevention.")

    # Simple Visual Flow (4 Steps)
    flow_steps = [
        ("PROPOSED CHANGE", "Firewall or IAM Ticket", BORDER_CYAN),
        ("SIMULATE", "Digital Twin in Memory", BORDER_CYAN),
        ("IDENTIFY RISK", "Blast Radius & Severity", BORDER_AMBER),
        ("SAFER DECISION", "Approve with Confidence", BORDER_GREEN),
    ]

    for idx, (title, sub, bcol) in enumerate(flow_steps):
        xp = 0.8 + idx * 3.05
        c_fl = add_card(s7, xp, 2.0, 2.55, 1.5, BG_CARD, bcol, 1.5)
        tf = c_fl.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = 'Arial'
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = TEXT_WHITE
        p.alignment = PP_ALIGN.CENTER
        p = tf.add_paragraph()
        p.text = sub
        p.font.size = Pt(8.5)
        p.font.color.rgb = TEXT_SILVER
        p.alignment = PP_ALIGN.CENTER

        if idx < 3:
            add_arrow(s7, xp + 2.62, 2.65, 0.38, 0.25, TEXT_CYAN)

    # Core Takeaway Banner (User requested exact text)
    takeaway = add_card(s7, 0.8, 3.85, 11.733, 1.1, RGBColor(16, 37, 66), BORDER_CYAN, 2)
    tf_t = takeaway.text_frame
    tf_t.word_wrap = True
    p = tf_t.paragraphs[0]
    p.text = "CORE TAKEAWAY"
    p.font.name = 'Arial'
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = TEXT_CYAN
    p.alignment = PP_ALIGN.CENTER

    p = tf_t.add_paragraph()
    p.text = "“SimuGuard AI moves security review from reactive detection to proactive prevention.”"
    p.font.name = 'Arial'
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    # Presenter & Closing Box
    pres_card = add_card(s7, 0.8, 5.25, 11.733, 1.5, BG_CARD_ALT, BORDER_DEFAULT, 1)
    tf_pr = pres_card.text_frame
    tf_pr.word_wrap = True
    p = tf_pr.paragraphs[0]
    p.text = "Ameya Shree Kasa — Security Engineer I    |    Abhiram Laha — Managed Service Engineer I"
    p.font.name = 'Arial'
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    p.alignment = PP_ALIGN.CENTER

    p = tf_pr.add_paragraph()
    p.text = "Apex Global Technologies Pre-Deployment Security Testbed  •  350 Automated Tests Passing"
    p.font.name = 'Arial'
    p.font.size = Pt(10)
    p.font.color.rgb = TEXT_MUTED
    p.alignment = PP_ALIGN.CENTER

    p = tf_pr.add_paragraph()
    p.text = "Thank You — We Welcome Your Questions"
    p.font.name = 'Arial'
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = TEXT_CYAN
    p.alignment = PP_ALIGN.CENTER

    set_notes(s7,
        "SPEAKER: Abhiram Laha (2:45 - 3:00 | 15s)\n\n"
        "[CLICK SLIDE 7]\n"
        "\"With 350 passing automated tests in our suite, SimuGuard AI proves that security changes can be tested safely and systematically before reaching production. "
        "It moves organizations from reactive firefighting to proactive prevention. "
        "Thank you, judges. We welcome your questions.\""
    )

    prs.save(output_path)
    print(f"Successfully generated: {output_path} (7 slides)")

if __name__ == '__main__':
    target = os.path.join("prestation docs tuesday", "SimuGuard_AI_3_Minute_Judge_Presentation.pptx")
    create_presentation(target)

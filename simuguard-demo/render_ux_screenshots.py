"""High-Fidelity Visual Renderer for SimuGuard AI Single-Workspace UX Redesign.

Generates 4 publication-grade PNG screenshots:
1. deliverables/screenshots/redesigned_sidebar.png
2. deliverables/screenshots/single_assessment_workspace.png
3. deliverables/screenshots/example_firewall_assessment.png
4. deliverables/screenshots/example_sailpoint_assessment.png
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

OUT_DIR = Path(__file__).resolve().parent / "deliverables" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Colors matching Enterprise Navy theme
NAVY = "#0f172a"
NAVY_ACTIVE = "#1e293b"
SLATE = "#334155"
LIGHT_BG = "#f8fafc"
BORDER_GRAY = "#e2e8f0"
TEXT_DARK = "#0f172a"
TEXT_MUTED = "#64748b"
PRIMARY_BLUE = "#0f62fe"
GREEN_ALLOW = "#10b981"
AMBER_WARN = "#f59e0b"
RED_BLOCK = "#ef4444"


def draw_box(ax, x, y, w, h, bg="#ffffff", border=BORDER_GRAY, lw=1.2, rx=0.015, zorder=2):
    """Draw a rounded rectangle."""
    rect = patches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad={rx}",
        linewidth=lw,
        edgecolor=border,
        facecolor=bg,
        zorder=zorder
    )
    ax.add_patch(rect)


def render_sidebar_screenshot():
    """Render the simplified enterprise sidebar screenshot."""
    fig, ax = plt.subplots(figsize=(6, 11), dpi=200)
    ax.set_facecolor(NAVY)
    fig.patch.set_facecolor(NAVY)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Header Branding
    ax.text(0.08, 0.94, "🛡️ SimuGuard AI", fontsize=15, fontweight="bold", color="#ffffff")
    ax.text(0.08, 0.91, "Enterprise Change Risk Engine", fontsize=9, color="#94a3b8")
    
    # Digital Twin status dot
    circle = plt.Circle((0.10, 0.88), 0.012, color=GREEN_ALLOW, zorder=3)
    ax.add_patch(circle)
    ax.text(0.13, 0.875, "Digital Twin: Apex Global (Online)", fontsize=8, color=GREEN_ALLOW, fontweight="bold")

    # Divider
    ax.plot([0.08, 0.92], [0.85, 0.85], color="#1e293b", lw=1.5)

    # Section Header: Main
    ax.text(0.08, 0.82, "WORKSPACE NAVIGATION", fontsize=8, fontweight="bold", color="#64748b")

    # Navigation Entry 1: New Assessment (Active)
    draw_box(ax, 0.06, 0.73, 0.88, 0.065, bg=NAVY_ACTIVE, border=PRIMARY_BLUE, lw=1.5)
    ax.text(0.12, 0.755, "⚡  New Assessment", fontsize=10.5, fontweight="bold", color="#ffffff")
    ax.text(0.72, 0.755, "DEFAULT", fontsize=7.5, fontweight="bold", color=PRIMARY_BLUE)

    # Navigation Entry 2: Assessment History
    draw_box(ax, 0.06, 0.64, 0.88, 0.065, bg=NAVY, border="#1e293b", lw=1)
    ax.text(0.12, 0.665, "📋  Assessment History", fontsize=10.5, color="#cbd5e1")

    # Navigation Entry 3: Reports
    draw_box(ax, 0.06, 0.55, 0.88, 0.065, bg=NAVY, border="#1e293b", lw=1)
    ax.text(0.12, 0.575, "📄  Reports", fontsize=10.5, color="#cbd5e1")

    # Section Header: Administration
    ax.text(0.08, 0.49, "ADMINISTRATION", fontsize=8, fontweight="bold", color="#64748b")

    # Navigation Entry 4: Settings & Diagnostics
    draw_box(ax, 0.06, 0.40, 0.88, 0.065, bg=NAVY, border="#1e293b", lw=1)
    ax.text(0.12, 0.425, "⚙️  Settings & Diagnostics", fontsize=10.5, color="#cbd5e1")

    # Clean Callout: Simplified Navigation
    draw_box(ax, 0.06, 0.22, 0.88, 0.14, bg="#1e293b", border="#334155", lw=1)
    ax.text(0.10, 0.32, "🛡️ Protected Sandbox Mode", fontsize=8.5, fontweight="bold", color=GREEN_ALLOW)
    ax.text(0.10, 0.28, "• Active DB: simuguard_demo.db\n• Multi-page clutter removed\n• Environment controls secured in Settings", fontsize=7.5, color="#94a3b8")

    # Tour toggle checkbox
    draw_box(ax, 0.08, 0.15, 0.03, 0.025, bg="#0f62fe", border="#0f62fe")
    ax.text(0.09, 0.155, "✓", fontsize=8, color="#ffffff", fontweight="bold")
    ax.text(0.13, 0.155, "Show Guided Demo Tour", fontsize=8, color="#cbd5e1")

    # Footer
    ax.plot([0.08, 0.92], [0.11, 0.11], color="#1e293b", lw=1.5)
    ax.text(0.08, 0.075, "Engine: SimuGuard Core 0.6.0", fontsize=7.5, color="#94a3b8")
    ax.text(0.08, 0.05, "Persistence: Local SQLite (Air-gapped)", fontsize=7.5, color="#64748b")

    out_path = OUT_DIR / "redesigned_sidebar.png"
    plt.tight_layout()
    plt.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print("Saved:", out_path)


def render_single_workspace_screenshot():
    """Render the full Single Assessment Workspace layout."""
    fig, ax = plt.subplots(figsize=(14, 11), dpi=200)
    ax.set_facecolor(LIGHT_BG)
    fig.patch.set_facecolor(LIGHT_BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Top Header Banner
    draw_box(ax, 0.03, 0.92, 0.94, 0.065, bg="#f0fdf4", border="#bbf7d0")
    ax.text(0.05, 0.945, "🛡️ Demo Sandbox Active: Modelled on Apex Global Technologies (220 nodes, 77 edges). Pre-seeded with 5 certified scenarios.", fontsize=9, color="#166534", fontweight="bold")

    # Workspace Title
    ax.text(0.03, 0.88, "Change Risk Assessment Workspace", fontsize=15, fontweight="bold", color=TEXT_DARK)
    ax.text(0.03, 0.855, "ServiceNow Pre-Flight Risk Engine • Single-Page Intake, Simulation, Remediation & Verification", fontsize=9, color=TEXT_MUTED)

    # Section 1: Change Request Input Card
    draw_box(ax, 0.03, 0.59, 0.94, 0.245, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.805, "1. Paste Change Request", fontsize=11, fontweight="bold", color=TEXT_DARK)
    ax.text(0.35, 0.807, "ServiceNow Intake & Extraction", fontsize=8, color=PRIMARY_BLUE)

    # Sample Quick Loaders
    draw_box(ax, 0.05, 0.755, 0.16, 0.035, bg="#f1f5f9", border="#cbd5e1")
    ax.text(0.06, 0.767, "📌 PR-4082 (DB Ingress)", fontsize=7.5, color=TEXT_DARK, fontweight="bold")
    draw_box(ax, 0.22, 0.755, 0.16, 0.035, bg="#f1f5f9", border="#cbd5e1")
    ax.text(0.23, 0.767, "📌 PR-4083 (DMZ & IAM)", fontsize=7.5, color=TEXT_DARK, fontweight="bold")
    draw_box(ax, 0.39, 0.755, 0.16, 0.035, bg="#f1f5f9", border="#cbd5e1")
    ax.text(0.40, 0.767, "📌 Netflix (Streaming)", fontsize=7.5, color=TEXT_DARK, fontweight="bold")
    draw_box(ax, 0.56, 0.755, 0.16, 0.035, bg="#f1f5f9", border="#cbd5e1")
    ax.text(0.57, 0.767, "📌 Safe Rule (Telemetry)", fontsize=7.5, color=TEXT_DARK, fontweight="bold")
    draw_box(ax, 0.73, 0.755, 0.16, 0.035, bg="#f1f5f9", border="#cbd5e1")
    ax.text(0.74, 0.767, "📌 SailPoint (S3 Access)", fontsize=7.5, color=TEXT_DARK, fontweight="bold")

    # Text Area box
    draw_box(ax, 0.05, 0.655, 0.90, 0.085, bg="#f8fafc", border="#cbd5e1")
    ax.text(0.06, 0.715, "Change Request: CHG004082\nShort Description: Allow direct database access for analytics data migration\nSource Zone: Untrust-Internet  |  Destination Zone: Prod-Database  |  CIDR: 0.0.0.0/0 -> 10.100.2.15/32\nApp-ID: any  |  Action: allow  |  Justification: Urgent analytics data pipeline ingestion", fontsize=7.5, family="monospace", color=SLATE)

    # Extraction Button
    draw_box(ax, 0.05, 0.605, 0.20, 0.038, bg=PRIMARY_BLUE, border=PRIMARY_BLUE)
    ax.text(0.08, 0.617, "🔍 Extract Configuration", fontsize=8.5, fontweight="bold", color="#ffffff")
    ax.text(0.28, 0.617, "Detected Domain: Network Security (Firewall / IAM) • Rule: direct-db-access-rule", fontsize=8, color="#059669")

    # Section 2: Review Configuration Card
    draw_box(ax, 0.03, 0.30, 0.94, 0.27, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.54, "2. Review Configuration", fontsize=11, fontweight="bold", color=TEXT_DARK)
    ax.text(0.35, 0.542, "Editable Extracted Fields & Ambiguity Detection", fontsize=8, color=TEXT_MUTED)

    # Inline Ambiguity Alert
    draw_box(ax, 0.05, 0.47, 0.90, 0.052, bg="#fffbeb", border="#fde68a")
    ax.text(0.065, 0.495, "⚠️ High-Risk Configuration Parameters Detected:", fontsize=8, fontweight="bold", color="#92400e")
    ax.text(0.065, 0.477, "• App-ID is set to 'any' (High risk of protocol evasion)   • Source 0.0.0.0/0 into Protected Database Zone violates PCI-DSS 1.3.1", fontsize=7.5, color="#92400e")

    # Configuration Fields Table Mock
    fields = [
        ("Short Description", "PR-4082: Allow Direct Database Ingress"),
        ("Change Domain", "Network Security / Firewall"),
        ("Priority", "CRITICAL"),
        ("Rule Name", "direct-db-access-rule"),
        ("Source Zone / CIDR", "Untrust-Internet (0.0.0.0/0)"),
        ("Destination Zone / CIDR", "Prod-Database (10.100.2.15/32)"),
        ("App-ID / Port", "any / 443 (service-https)"),
        ("Action", "allow"),
    ]
    for i, (k, v) in enumerate(fields):
        col = i % 4
        row = i // 4
        bx = 0.05 + col * 0.225
        by = 0.38 - row * 0.065
        draw_box(ax, bx, by, 0.21, 0.052, bg="#f8fafc", border="#cbd5e1")
        ax.text(bx + 0.01, by + 0.035, k, fontsize=6.8, fontweight="bold", color="#475569")
        ax.text(bx + 0.01, by + 0.012, v, fontsize=7.5, color=TEXT_DARK)

    # Section 3: Run Assessment Card
    draw_box(ax, 0.03, 0.16, 0.94, 0.12, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.38, 0.245, "3. Run Pre-Flight Assessment", fontsize=11, fontweight="bold", color=TEXT_DARK)
    ax.text(0.24, 0.225, "Simulates change against Digital Twin topology, evaluates security rules, predicts blast-radius impact,", fontsize=8, color=TEXT_MUTED)
    ax.text(0.33, 0.210, "and executes closed-loop remediation validation automatically.", fontsize=8, color=TEXT_MUTED)

    draw_box(ax, 0.35, 0.175, 0.30, 0.035, bg=PRIMARY_BLUE, border=PRIMARY_BLUE)
    ax.text(0.40, 0.185, "🚀 Run Pre-Flight Assessment", fontsize=9.5, fontweight="bold", color="#ffffff")

    # Section 4: Results Tabs preview
    draw_box(ax, 0.03, 0.02, 0.94, 0.12, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.105, "4. Pre-Flight Assessment Results & Remediation (Inline)", fontsize=11, fontweight="bold", color=TEXT_DARK)
    tabs = ["🔍 Findings & Assets (3)", "🌐 Digital Twin Blast Radius (14)", "🛠️ Remediation & Patch", "⚖️ Before & After", "📄 Export Reports"]
    for i, t in enumerate(tabs):
        draw_box(ax, 0.05 + i * 0.18, 0.045, 0.17, 0.04, bg=LIGHT_BG if i > 0 else "#eff6ff", border=PRIMARY_BLUE if i == 0 else BORDER_GRAY)
        ax.text(0.06 + i * 0.18, 0.06, t, fontsize=7.5, fontweight="bold" if i == 0 else "normal", color=PRIMARY_BLUE if i == 0 else TEXT_DARK)

    out_path = OUT_DIR / "single_assessment_workspace.png"
    plt.tight_layout()
    plt.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print("Saved:", out_path)


def render_firewall_assessment_screenshot():
    """Render comprehensive screenshot of firewall assessment results (PR-4082)."""
    fig, ax = plt.subplots(figsize=(14, 11), dpi=200)
    ax.set_facecolor(LIGHT_BG)
    fig.patch.set_facecolor(LIGHT_BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Verdict Banner
    draw_box(ax, 0.03, 0.86, 0.94, 0.11, bg="#fef2f2", border=RED_BLOCK, lw=2)
    ax.text(0.05, 0.935, "PRE-FLIGHT SIMULATION DECISION GATE • SIM-CHG-001 (PR-4082)", fontsize=8, fontweight="bold", color="#991b1b")
    draw_box(ax, 0.72, 0.915, 0.23, 0.035, bg=RED_BLOCK, border=RED_BLOCK)
    ax.text(0.74, 0.925, "✕ VERDICT: BLOCK DEPLOYMENT", fontsize=8, fontweight="bold", color="#ffffff")
    ax.text(0.05, 0.895, "CRITICAL SECURITY VIOLATIONS DETECTED (Risk Score: 100/100)", fontsize=13, fontweight="bold", color="#991b1b")
    ax.text(0.05, 0.872, "Unrestricted perimeter ingress into PCI-DSS Database Tier with wildcard App-ID and AWS Admin policy attachment.", fontsize=8.5, color="#7f1d1d")

    # Metric KPI Cards
    kpis = [
        ("Baseline Risk Score", "100/100", "CRITICAL Severity Tier"),
        ("Security Gaps", "3 Gaps", "2 Critical, 1 High"),
        ("Affected Assets", "14 Assets", "Direct & Indirect Reach"),
        ("Candidate Risk Score", "0/100", "After Least-Privilege Patch"),
        ("Net Risk Reduction", "-100 pts", "Closed-Loop Validation: ALLOW"),
    ]
    for i, (label, val, hint) in enumerate(kpis):
        bx = 0.03 + i * 0.192
        draw_box(ax, bx, 0.76, 0.18, 0.085, bg="#ffffff", border=BORDER_GRAY)
        ax.text(bx + 0.015, 0.825, label, fontsize=7.5, color=TEXT_MUTED, fontweight="bold")
        ax.text(bx + 0.015, 0.795, val, fontsize=13, color=RED_BLOCK if i == 0 else (GREEN_ALLOW if i >= 3 else TEXT_DARK), fontweight="bold")
        ax.text(bx + 0.015, 0.77, hint, fontsize=6.8, color="#475569")

    # Security Findings Table
    draw_box(ax, 0.03, 0.44, 0.94, 0.30, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.705, "Security Findings (Gaps Identified by RiskEngine)", fontsize=11, fontweight="bold", color=TEXT_DARK)
    
    findings = [
        ("RULE-FW-01", "CRITICAL", "Direct Internet Ingress to PCI Database Tier", "0.0.0.0/0 route to prod-db violates PCI-DSS 1.3.1 network segregation.", "Restrict destination CIDR to authorized subnets via DMZ proxy."),
        ("RULE-FW-02", "CRITICAL", "Palo Alto Layer-7 App-ID Bypass (any)", "Setting applications to 'any' allows arbitrary protocol tunneling on 443.", "Scope App-ID strictly to approved signatures ['ssl', 'web-browsing']."),
        ("RULE-IAM-01", "HIGH", "Wildcard IAM AdministratorAccess Attachment", "Attaching AdministratorAccess to service role violates least-privilege.", "Replace managed admin policy with scoped S3ReadOnly / TelemetryWriter policy."),
    ]
    for idx, (rid, sev, title, impact, rem) in enumerate(findings):
        fy = 0.61 - idx * 0.08
        draw_box(ax, 0.05, fy, 0.90, 0.075, bg="#f8fafc", border=BORDER_GRAY)
        draw_box(ax, 0.06, fy + 0.045, 0.08, 0.022, bg=RED_BLOCK if sev == "CRITICAL" else AMBER_WARN, border=RED_BLOCK if sev == "CRITICAL" else AMBER_WARN)
        ax.text(0.065, fy + 0.05, f"{sev}", fontsize=6.5, color="#ffffff", fontweight="bold")
        ax.text(0.15, fy + 0.05, f"[{rid}] {title}", fontsize=8.5, fontweight="bold", color=TEXT_DARK)
        ax.text(0.06, fy + 0.028, f"Technical Impact: {impact}", fontsize=7.2, color=SLATE)
        ax.text(0.06, fy + 0.010, f"💡 Remediation: {rem}", fontsize=7.2, color="#059669", fontweight="bold")

    # Remediation & Comparison Section
    draw_box(ax, 0.03, 0.17, 0.46, 0.25, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.39, "🛠️ Synthesized Candidate Configuration", fontsize=10.5, fontweight="bold", color=TEXT_DARK)
    draw_box(ax, 0.05, 0.19, 0.42, 0.18, bg="#0f172a", border="#1e293b")
    hcl_sample = """# Synthesized by SimuGuard ConfigGenerator
resource "panos_security_policy" "scoped_rule" {
  destination_addresses = ["52.84.120.0/22"] # Scoped CIDR
  applications          = ["ssl"]            # Enforced App-ID
  security_profile_group = "corporate-threat-prevention"
}
resource "aws_iam_role_policy_attachment" "least_privilege" {
  policy_arn = "arn:aws:iam::123:policy/TelemetryWriterPolicy"
}"""
    ax.text(0.06, 0.21, hcl_sample, fontsize=6.8, family="monospace", color="#38bdf8")

    draw_box(ax, 0.51, 0.17, 0.46, 0.25, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.53, 0.39, "⚖️ Before & After Differential Comparison", fontsize=10.5, fontweight="bold", color=TEXT_DARK)
    draw_box(ax, 0.53, 0.30, 0.42, 0.07, bg="#f0fdf4", border="#bbf7d0")
    ax.text(0.55, 0.345, "Risk Reduction: 100 → 0 (-100 pts)  |  Verdict: BLOCK -> ALLOW", fontsize=8, fontweight="bold", color="#166534")
    ax.text(0.55, 0.315, "• 3/3 Policy Violations Resolved Cleanly   • Blast Radius Contraction: 14 -> 2 Nodes", fontsize=7.5, color="#166534")
    ax.text(0.53, 0.26, "Closed-Loop Validation Checks:", fontsize=8, fontweight="bold", color=TEXT_DARK)
    ax.text(0.53, 0.23, "✅ VAL-CHK-01: Destination CIDR restricted to verified endpoint", fontsize=7.2, color="#059669")
    ax.text(0.53, 0.205, "✅ VAL-CHK-02: Palo Alto App-ID deep inspection enabled", fontsize=7.2, color="#059669")
    ax.text(0.53, 0.18, "✅ VAL-CHK-03: Cloud IAM wildcard admin policy replaced with scoped role", fontsize=7.2, color="#059669")

    # One-Click Export Toolbar
    draw_box(ax, 0.03, 0.03, 0.94, 0.12, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.115, "📄 One-Click Compliance & Audit Exports (Generated Directly on Workspace)", fontsize=10.5, fontweight="bold", color=TEXT_DARK)
    draw_box(ax, 0.05, 0.05, 0.42, 0.05, bg=PRIMARY_BLUE, border=PRIMARY_BLUE)
    ax.text(0.12, 0.068, "📥 Download Executive PDF Report (CAB Audit)", fontsize=8.5, fontweight="bold", color="#ffffff")
    draw_box(ax, 0.53, 0.05, 0.42, 0.05, bg="#1e293b", border="#334155")
    ax.text(0.61, 0.068, "📥 Download Audit JSON Export (CI/CD Artifact)", fontsize=8.5, fontweight="bold", color="#ffffff")

    out_path = OUT_DIR / "example_firewall_assessment.png"
    plt.tight_layout()
    plt.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print("Saved:", out_path)


def render_sailpoint_assessment_screenshot():
    """Render comprehensive screenshot of SailPoint access governance assessment."""
    fig, ax = plt.subplots(figsize=(14, 11), dpi=200)
    ax.set_facecolor(LIGHT_BG)
    fig.patch.set_facecolor(LIGHT_BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Verdict Banner
    draw_box(ax, 0.03, 0.86, 0.94, 0.11, bg="#fffbeb", border=AMBER_WARN, lw=2)
    ax.text(0.05, 0.935, "IDENTITY GOVERNANCE SIMULATION DECISION GATE • CHG009941", fontsize=8, fontweight="bold", color="#92400e")
    draw_box(ax, 0.70, 0.915, 0.25, 0.035, bg=AMBER_WARN, border=AMBER_WARN)
    ax.text(0.72, 0.925, "▲ VERDICT: WARN (MANUAL CAB REVIEW)", fontsize=8, fontweight="bold", color="#ffffff")
    ax.text(0.05, 0.895, "PRIVILEGED CONTRACTOR ACCESS & IN-FLIGHT GOVERNANCE WARNING (Score: 85/100)", fontsize=13, fontweight="bold", color="#92400e")
    ax.text(0.05, 0.872, "Target Identity: Sarah Chen (Contractor) requesting Production S3 CUI Vault Read Access while in PENDING state.", fontsize=8.5, color="#78350f")

    # Metric KPI Cards
    kpis = [
        ("Governance Risk Score", "85/100", "HIGH Severity Tier"),
        ("Identity Rule Gaps", "2 Gaps", "SP-01 In-Flight, SP-03 Contractor"),
        ("Data Assets Exposed", "1 Critical Vault", "Classified CUI Finance Data"),
        ("Approval Gate", "PENDING", "Multi-Tier CAB Sign-Off Required"),
        ("Identity Source", "Active Directory", "Authoritative Directory Correlated"),
    ]
    for i, (label, val, hint) in enumerate(kpis):
        bx = 0.03 + i * 0.192
        draw_box(ax, bx, 0.76, 0.18, 0.085, bg="#ffffff", border=BORDER_GRAY)
        ax.text(bx + 0.015, 0.825, label, fontsize=7.5, color=TEXT_MUTED, fontweight="bold")
        ax.text(bx + 0.015, 0.795, val, fontsize=12, color=AMBER_WARN if i == 0 else TEXT_DARK, fontweight="bold")
        ax.text(bx + 0.015, 0.77, hint, fontsize=6.8, color="#475569")

    # Governance Findings Table
    draw_box(ax, 0.03, 0.44, 0.94, 0.30, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.705, "SailPoint ISC Rule Evaluation Findings", fontsize=11, fontweight="bold", color=TEXT_DARK)
    
    findings = [
        ("SP-01", "CRITICAL", "In-Flight / Unapproved Access Assumption (PENDING_IS_NOT_ACCESS)", "Access request is currently in 'PENDING_APPROVAL' state. Pre-flight simulation enforces zero access conveyance until formal sign-off.", "Mandate multi-tier manager and information security owner approval in SailPoint ISC before role assignment."),
        ("SP-03", "HIGH", "Contractor Privileged CUI Vault Read Access Attempt", "Employment type 'CONTRACTOR' requesting elevated financial CUI entitlement violates segregation baseline.", "Verify NDA clearance and implement 30-day time-bound expiring access profile with session auditing."),
    ]
    for idx, (rid, sev, title, impact, rem) in enumerate(findings):
        fy = 0.58 - idx * 0.11
        draw_box(ax, 0.05, fy, 0.90, 0.10, bg="#f8fafc", border=BORDER_GRAY)
        draw_box(ax, 0.06, fy + 0.068, 0.08, 0.022, bg=RED_BLOCK if sev == "CRITICAL" else AMBER_WARN, border=RED_BLOCK if sev == "CRITICAL" else AMBER_WARN)
        ax.text(0.065, fy + 0.073, f"{sev}", fontsize=6.5, color="#ffffff", fontweight="bold")
        ax.text(0.15, fy + 0.073, f"[{rid}] {title}", fontsize=8.5, fontweight="bold", color=TEXT_DARK)
        ax.text(0.06, fy + 0.043, f"Technical Impact: {impact}", fontsize=7.2, color=SLATE)
        ax.text(0.06, fy + 0.018, f"💡 Remediation: {rem}", fontsize=7.2, color="#059669", fontweight="bold")

    # Identity Correlation & Asset Scope
    draw_box(ax, 0.03, 0.17, 0.46, 0.25, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.39, "👤 Authoritative Directory Correlation", fontsize=10.5, fontweight="bold", color=TEXT_DARK)
    draw_box(ax, 0.05, 0.19, 0.42, 0.18, bg="#f8fafc", border="#cbd5e1")
    id_info = """• Display Name: Sarah Chen (Contractor)
• SailPoint Identity ID: sp-ident-sarah-chen
• Identity Profile: Contractor & Vendor Workforce
• Employment Status: Active (Vendor Audit Assignment)
• Target Source: Corporate Active Directory (sp-acct-ad-sarah-chen)
• Requested Role: Finance & Treasury Analyst
• Entitlement: AWS Production S3 CUI Vault Read (Vault-Finance-01)
• SoD Matrix Conflict: Checked (No toxic combination detected)"""
    ax.text(0.06, 0.20, id_info, fontsize=7.2, color=TEXT_DARK)

    draw_box(ax, 0.51, 0.17, 0.46, 0.25, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.53, 0.39, "🌐 Digital Twin Impact Scope & CAB Validation", fontsize=10.5, fontweight="bold", color=TEXT_DARK)
    draw_box(ax, 0.53, 0.30, 0.42, 0.07, bg="#fffbeb", border="#fde68a")
    ax.text(0.55, 0.345, "Target Asset: AWS Production S3 CUI Financial Vault", fontsize=8, fontweight="bold", color="#92400e")
    ax.text(0.55, 0.315, "• Data Classification: CUI / Sensitive Financial  • Tier: Core Data Asset", fontsize=7.5, color="#78350f")
    ax.text(0.53, 0.26, "CAB Approval Requirements:", fontsize=8, fontweight="bold", color=TEXT_DARK)
    ax.text(0.53, 0.23, "⚠️ 1. Requires Information Security Officer (ISO) explicit sign-off", fontsize=7.2, color="#b45309")
    ax.text(0.53, 0.205, "⚠️ 2. Mandatory access expiration date required (Max 90 days)", fontsize=7.2, color="#b45309")
    ax.text(0.53, 0.18, "✅ 3. Authoritative active directory status verified active", fontsize=7.2, color="#059669")

    # One-Click Export Toolbar
    draw_box(ax, 0.03, 0.03, 0.94, 0.12, bg="#ffffff", border=BORDER_GRAY)
    ax.text(0.05, 0.115, "📄 Compliance & Governance Reports (Ready for Download)", fontsize=10.5, fontweight="bold", color=TEXT_DARK)
    draw_box(ax, 0.05, 0.05, 0.42, 0.05, bg=PRIMARY_BLUE, border=PRIMARY_BLUE)
    ax.text(0.12, 0.068, "📥 Download Executive PDF Report (CAB Sign-off)", fontsize=8.5, fontweight="bold", color="#ffffff")
    draw_box(ax, 0.53, 0.05, 0.42, 0.05, bg="#1e293b", border="#334155")
    ax.text(0.61, 0.068, "📥 Download Audit JSON Export (SailPoint Telemetry)", fontsize=8.5, fontweight="bold", color="#ffffff")

    out_path = OUT_DIR / "example_sailpoint_assessment.png"
    plt.tight_layout()
    plt.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print("Saved:", out_path)


if __name__ == "__main__":
    render_sidebar_screenshot()
    render_single_workspace_screenshot()
    render_firewall_assessment_screenshot()
    render_sailpoint_assessment_screenshot()
    print("All 4 UX redesign screenshots successfully generated!")

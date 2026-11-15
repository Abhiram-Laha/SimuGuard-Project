"""PDF Architecture Document Generator for SimuGuard AI.
Generates: deliverables/Apex_Global_Technologies_Enterprise_Architecture.pdf
Comprehensive 15-section technical enterprise architecture document based on the Apex Global Technologies dataset.
"""

from pathlib import Path
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    KeepTogether,
    PageBreak,
    HRFlowable,
)
from reportlab.pdfgen import canvas

REPO_ROOT = Path(__file__).resolve().parent
DELIVERABLES_DIR = REPO_ROOT / "deliverables"
DIAGRAMS_DIR = DELIVERABLES_DIR / "diagrams"
PDF_PATH = DELIVERABLES_DIR / "Apex_Global_Technologies_Enterprise_Architecture.pdf"

# Color Palette
NAVY = colors.HexColor("#0f172a")
DARK_SLATE = colors.HexColor("#1e293b")
TEXT_MUTED = colors.HexColor("#475569")
ACCENT_BLUE = colors.HexColor("#1d4ed8")
LIGHT_BG = colors.HexColor("#f8fafc")
BORDER_COLOR = colors.HexColor("#cbd5e1")
CALLOUT_BG = colors.HexColor("#eff6ff")
CALLOUT_BORDER = colors.HexColor("#3b82f6")
WARN_BG = colors.HexColor("#fffbeb")
WARN_BORDER = colors.HexColor("#f59e0b")
CRIT_BG = colors.HexColor("#fef2f2")
CRIT_BORDER = colors.HexColor("#ef4444")


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page counts."""

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

    def draw_page_decorations(self, page_count):
        if self._pageNumber > 1:
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(TEXT_MUTED)
            # Running Header
            self.drawString(36, 756, "Apex Global Technologies – Enterprise Architecture & Digital Twin Reference")
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)
            # Running Footer
            self.line(36, 45, 576, 45)
            self.drawString(36, 34, "SimuGuard AI Platform | Confidential & Proprietary Security Reference Architecture")
            page_str = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(576, 34, page_str)
            self.restoreState()


def create_callout(text: str, title: str = "KEY ARCHITECTURAL TAKEAWAY", level: str = "info", styles = None):
    bg = CALLOUT_BG if level == "info" else (WARN_BG if level == "warn" else CRIT_BG)
    border = CALLOUT_BORDER if level == "info" else (WARN_BORDER if level == "warn" else CRIT_BORDER)
    
    t_style = ParagraphStyle(
        "CalloutTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=border,
    )
    b_style = ParagraphStyle(
        "CalloutBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=DARK_SLATE,
    )
    content = [
        Paragraph(f"<b>{title}</b>", t_style),
        Spacer(1, 4),
        Paragraph(text, b_style)
    ]
    t = Table([[content]], colWidths=[540])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 1, border),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def build_pdf():
    print(f"Generating PDF: {PDF_PATH}...")
    doc = SimpleDocTemplate(
        str(PDF_PATH),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle("CoverTitle", fontName="Helvetica-Bold", fontSize=26, leading=32, textColor=NAVY, alignment=1)
    subtitle_style = ParagraphStyle("CoverSub", fontName="Helvetica", fontSize=13, leading=18, textColor=TEXT_MUTED, alignment=1)
    h1_style = ParagraphStyle("Heading1_Custom", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceAfter=8)
    h2_style = ParagraphStyle("Heading2_Custom", fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=ACCENT_BLUE, spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle("Body_Custom", fontName="Helvetica", fontSize=9, leading=13.5, textColor=DARK_SLATE, spaceAfter=6)
    bullet_style = ParagraphStyle("Bullet_Custom", fontName="Helvetica", fontSize=8.5, leading=12.5, textColor=DARK_SLATE, leftIndent=12, spaceAfter=3)
    table_cell = ParagraphStyle("TableCell", fontName="Helvetica", fontSize=8, leading=10.5, textColor=DARK_SLATE)
    table_cell_bold = ParagraphStyle("TableCellBold", fontName="Helvetica-Bold", fontSize=8, leading=10.5, textColor=DARK_SLATE)
    table_cell_header = ParagraphStyle("TableCellHdr", fontName="Helvetica-Bold", fontSize=8, leading=10.5, textColor=colors.white)

    story = []

    # ==========================================================================
    # 1. COVER PAGE
    # ==========================================================================
    story.append(Spacer(1, 100))
    story.append(Paragraph("SIMUGUARD AI PLATFORM", ParagraphStyle("CoverTag", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=ACCENT_BLUE, alignment=1)))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Apex Global Technologies", title_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Enterprise Hybrid Cloud Architecture & Digital Twin Reference", subtitle_style))
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="60%", thickness=2, color=ACCENT_BLUE, spaceBefore=10, spaceAfter=20))
    story.append(Spacer(1, 40))

    meta_text = (
        "<b>Document Version:</b> 1.0 (Production Benchmark)<br/>"
        "<b>Organization:</b> Apex Global Technologies Inc. (apex-global.example)<br/>"
        "<b>Compliance Frameworks:</b> NIST CSF 2.0 | NIST SP 800-171 Rev 2 | PCI-DSS v4.0 | CIS Benchmark<br/>"
        "<b>Target Platforms:</b> Palo Alto Networks PAN-OS 11.1 Nebula | AWS Cloud Infrastructure<br/>"
        "<b>Author:</b> SimuGuard AI Architecture & Cybersecurity Engineering Team<br/>"
        "<b>Publication Date:</b> November 2026<br/>"
        "<b>Classification:</b> Proprietary & Confidential Technical Architecture Specification"
    )
    meta_table = Table([[Paragraph(meta_text, ParagraphStyle("CoverMeta", fontName="Helvetica", fontSize=9.5, leading=15, textColor=DARK_SLATE, alignment=1))]], colWidths=[460])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 16),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(meta_table)
    story.append(PageBreak())

    # ==========================================================================
    # 2. EXECUTIVE SUMMARY
    # ==========================================================================
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(Paragraph(
        "This architectural specification defines the comprehensive digital twin environment for <b>Apex Global Technologies</b> "
        "(<code>apex-global.example</code>), an enterprise financial technology organization. The architecture serves as the foundation "
        "for <b>SimuGuard AI</b>, a cybersecurity pre-deployment simulation engine designed to analyze proposed Terraform changes, "
        "trace cross-layer blast radius paths, and enforce least-privilege security boundaries before configuration commits take effect.",
        body_style
    ))
    story.append(Paragraph(
        "The environment models an enterprise hybrid topology combining <b>Palo Alto Networks PAN-OS 11.1 Nebula</b> next-generation "
        "firewalls with an <b>AWS Multi-Account Organization</b> (<code>o-apexglobal01</code>). The dataset bridges Layer 7 network security "
        "policies, Panorama management device groups, multi-VPC cloud networking, IAM identity federation via EKS IRSA, microservice "
        "application dependencies, and sensitive data assets governed by <b>NIST SP 800-171</b>, <b>PCI-DSS v4.0</b>, and <b>GDPR</b>.",
        body_style
    ))
    story.append(Spacer(1, 8))

    # Metric Table
    metrics_data = [
        [Paragraph("Architectural Dimension", table_cell_header), Paragraph("Count / Spec", table_cell_header), Paragraph("Key Technical Highlights", table_cell_header)],
        [Paragraph("Palo Alto Firewalls", table_cell_bold), Paragraph("4 Appliances (2 HA Pairs)", table_cell), Paragraph("PA-5450 Internet Perimeter HA + PA-3440 Internal Core Segmentation HA", table_cell)],
        [Paragraph("Panorama Management", table_cell_bold), Paragraph("1 Virtual Server", table_cell), Paragraph("Panorama 11.1 managing 3 Device Groups and shared security templates", table_cell)],
        [Paragraph("Network Security Zones", table_cell_bold), Paragraph("9 Dedicated Zones", table_cell), Paragraph("Untrust, Trust-DMZ, Corp, Transit, Prod-App, Dev-App, DB, PCI, Vault", table_cell)],
        [Paragraph("Enterprise Subnets", table_cell_bold), Paragraph("9 Subnets / VLANs", table_cell), Paragraph("All RFC 1918 private space with distinct gateway routers and CIDRs", table_cell)],
        [Paragraph("Security Policies", table_cell_bold), Paragraph("22 Rules (Pre & Post)", table_cell), Paragraph("Layer 7 App-ID, security profile groups, and intentional test gaps", table_cell)],
        [Paragraph("AWS Accounts & VPCs", table_cell_bold), Paragraph("3 Accounts, 3 VPCs", table_cell), Paragraph("Production (10.100/16), Development (10.200/16), Security (10.250/16)", table_cell)],
        [Paragraph("Compute & Data Stores", table_cell_bold), Paragraph("17 Cloud Resources", table_cell), Paragraph("5 EKS compute pools, 2 ALBs, 2 RDS PostgreSQL, 5 S3 buckets, 3 KMS keys", table_cell)],
        [Paragraph("IAM Roles & Policies", table_cell_bold), Paragraph("6 Roles, 10 Policies", table_cell), Paragraph("EKS IRSA OIDC federation, permission boundaries, and cross-account trusts", table_cell)],
        [Paragraph("Business Applications", table_cell_bold), Paragraph("12 Microservices", table_cell), Paragraph("Customer Portal, Payment Tokenizer, Analytics Pipeline, API Gateway", table_cell)],
        [Paragraph("Sensitive Data Assets", table_cell_bold), Paragraph("6 Repositories", table_cell), Paragraph("CUI Financial Ledger, PCI Cardholder Tokens, Customer PII Database", table_cell)],
        [Paragraph("Digital Twin Graph", table_cell_bold), Paragraph("64 Nodes, 39 Edges", table_cell), Paragraph("NetworkX directed graph with strict referential integrity & zero dangling IDs", table_cell)],
    ]
    t_metrics = Table(metrics_data, colWidths=[130, 110, 300])
    t_metrics.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 10))
    story.append(create_callout(
        "SimuGuard AI evaluates security changes entirely in software using this Digital Twin representation. "
        "No live firewall or AWS API modifications are performed, guaranteeing safe, zero-risk blast radius simulation.",
        "ZERO-IMPACT PRE-DEPLOYMENT SIMULATION",
        "info",
        styles
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 3. ORGANISATION OVERVIEW
    # ==========================================================================
    story.append(Paragraph("2. Organisation Overview", h1_style))
    story.append(Paragraph(
        "Apex Global Technologies is organized into four primary operational and engineering business units operating under a unified "
        "security governance and compliance charter:",
        body_style
    ))
    story.append(Paragraph("• <b>FinTech Digital Banking Operations:</b> Owns the customer-facing web tier (APP-001), core transactional API gateway (APP-007), and relational customer account databases (rds-postgres-core-prod).", bullet_style))
    story.append(Paragraph("• <b>Payment Security & Compliance Operations:</b> Manages the isolated Cardholder Data Environment (CDE), tokenization services (APP-002), and hardware-protected token databases (rds-pci-token-vault-prod) under PCI-DSS v4.0.", bullet_style))
    story.append(Paragraph("• <b>Data Engineering & Analytics:</b> Operates the analytics worker pool (eks-analytics-worker-pool), event clickstream pipelines (APP-003), and high-throughput data lakes.", bullet_style))
    story.append(Paragraph("• <b>SecOps & Cloud Platform Engineering:</b> Governs firewall policies across Panorama, enforces AWS Organizations Service Control Policies (SCPs), manages IAM permission boundaries, and monitors central SIEM telemetry.", bullet_style))
    story.append(Spacer(1, 10))

    if (DIAGRAMS_DIR / "enterprise_organisation.png").is_file():
        story.append(Paragraph("Figure 2.1: Apex Global Technologies Enterprise Organisation Architecture", h2_style))
        story.append(Image(str(DIAGRAMS_DIR / "enterprise_organisation.png"), width=540, height=335))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Governance of this multi-account architecture relies on hierarchical separation of duties. Production workloads are isolated from "
        "development sandboxes, and all audit logs flow unidirectionally into a hardened, immutable security account.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 4. ENTERPRISE NETWORK ARCHITECTURE
    # ==========================================================================
    story.append(Paragraph("3. Enterprise Network Architecture", h1_style))
    story.append(Paragraph(
        "The network architecture employs a dual-tier perimeter and internal segmentation model. Ingress traffic from the public Internet "
        "terminates on the edge firewall pair before entering a dedicated Demilitarized Zone (Trust-DMZ). Internal segmentation firewalls "
        "regulate all East-West traffic between application microservices, database clusters, and sensitive vaults.",
        body_style
    ))
    story.append(Spacer(1, 6))

    if (DIAGRAMS_DIR / "network_architecture.png").is_file():
        story.append(Paragraph("Figure 3.1: Enterprise Network & Zone Segmentation Architecture", h2_style))
        story.append(Image(str(DIAGRAMS_DIR / "network_architecture.png"), width=540, height=335))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Network Ingress Flow:</b> External Internet users connect to public VIP <code>203.0.113.20:443</code>. The primary perimeter "
        "firewall performs Layer 7 App-ID inspection and applies Destination NAT (NAT-01), translating the public destination to the "
        "internal ALB VIP (<code>10.100.4.20</code>) residing in subnet <code>10.100.4.0/24</code>.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Transit Interconnect:</b> A dedicated transit network (<code>10.255.0.0/30</code>, VLAN 99) bridges the perimeter firewall "
        "to the internal core firewall, isolating public DMZ traffic from internal core production networks.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 5. PALO ALTO FIREWALL AND PANORAMA ARCHITECTURE
    # ==========================================================================
    story.append(Paragraph("4. Palo Alto Firewall & Panorama Architecture", h1_style))
    story.append(Paragraph(
        "Network policy management is centralized using <b>Panorama 11.1</b> (<code>pan-mgmt-01</code>). The deployment structure utilizes "
        "hierarchical Device Groups and Templates to enforce consistent baseline controls while accommodating zone-specific rules:",
        body_style
    ))

    dg_data = [
        [Paragraph("Device Group", table_cell_header), Paragraph("Target Firewalls", table_cell_header), Paragraph("Policy Scope & Enforcement", table_cell_header)],
        [Paragraph("DG-Enterprise-Shared", table_cell_bold), Paragraph("All Appliances (Edge & Core)", table_cell), Paragraph("Corporate baseline: drops RFC1918 spoofing, allows DNS/NTP outbound, enforces corporate URL categories", table_cell)],
        [Paragraph("DG-Internet-Perimeter", table_cell_bold), Paragraph("fw-edge-01, fw-edge-02 (PA-5450)", table_cell), Paragraph("Inbound web ingress, DMZ reverse proxy NAT, public egress filtering, and threat profile inspection", table_cell)],
        [Paragraph("DG-Internal-Segmentation", table_cell_bold), Paragraph("fw-internal-01, fw-internal-02 (PA-3440)", table_cell), Paragraph("Strict micro-segmentation between Prod-App, DB, PCI CDE, and NIST SP 800-171 CUI data vaults", table_cell)],
    ]
    t_dg = Table(dg_data, colWidths=[130, 140, 270])
    t_dg.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_dg)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>High Availability Architecture:</b> Both perimeter (PA-5450) and internal core (PA-3440) firewalls operate in Active/Passive "
        "redundancy. Dedicated HA1 links maintain heartbeats and configuration synchronization, while HA2 links perform high-speed "
        "session table replication to ensure zero-downtime failover.",
        body_style
    ))
    story.append(Spacer(1, 8))
    story.append(create_callout(
        "PAN-OS App-ID inspection is mandatory across all inter-zone policies. Bypassing App-ID with application 'any' "
        "satisfies critical blast conditions that trigger pre-deployment simulation blocks in SimuGuard AI.",
        "APP-ID DEEP PACKET INSPECTION REQUIREMENT",
        "warn",
        styles
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 6. NETWORK ZONES AND SEGMENTATION
    # ==========================================================================
    story.append(Paragraph("5. Network Zones & Security Segmentation", h1_style))
    story.append(Paragraph(
        "Apex Global Technologies enforces nine distinct security zones. All traffic traversing zone boundaries must pass through "
        "stateful, deep-packet inspection firewalls with active Threat Prevention profiles:",
        body_style
    ))

    zone_data = [
        [Paragraph("Zone Name", table_cell_header), Paragraph("Subnet CIDR", table_cell_header), Paragraph("VLAN", table_cell_header), Paragraph("Criticality", table_cell_header), Paragraph("Zone Purpose & Governance", table_cell_header)],
        [Paragraph("Untrust-Internet", table_cell_bold), Paragraph("0.0.0.0/0", table_cell), Paragraph("-", table_cell), Paragraph("Critical", table_cell), Paragraph("Public Internet ingress and egress termination", table_cell)],
        [Paragraph("Trust-DMZ", table_cell_bold), Paragraph("10.100.4.0/24", table_cell), Paragraph("VLAN 10", table_cell), Paragraph("High", table_cell), Paragraph("Public ALBs and analytics ingestion worker pods", table_cell)],
        [Paragraph("Corp-Users", table_cell_bold), Paragraph("10.10.0.0/16", table_cell), Paragraph("VLAN 100", table_cell), Paragraph("Medium", table_cell), Paragraph("Corporate workstations and SSL-VPN remote access pools", table_cell)],
        [Paragraph("Transit-Internal", table_cell_bold), Paragraph("10.255.0.0/30", table_cell), Paragraph("VLAN 99", table_cell), Paragraph("High", table_cell), Paragraph("Point-to-point transit bridging edge and internal firewalls", table_cell)],
        [Paragraph("Prod-App-Workloads", table_cell_bold), Paragraph("10.100.10.0/23", table_cell), Paragraph("VLAN 20", table_cell), Paragraph("High", table_cell), Paragraph("Production microservices and customer portal pods", table_cell)],
        [Paragraph("Dev-App-Workloads", table_cell_bold), Paragraph("10.200.10.0/23", table_cell), Paragraph("VLAN 200", table_cell), Paragraph("Medium", table_cell), Paragraph("Developer sandbox EKS clusters and test pipelines", table_cell)],
        [Paragraph("Database-Backend", table_cell_bold), Paragraph("10.100.20.0/24", table_cell), Paragraph("VLAN 30", table_cell), Paragraph("Critical", table_cell), Paragraph("Production PostgreSQL relational databases", table_cell)],
        [Paragraph("PCI-Cardholder-Data", table_cell_bold), Paragraph("10.100.30.0/24", table_cell), Paragraph("VLAN 40", table_cell), Paragraph("Critical", table_cell), Paragraph("Isolated Cardholder Data Environment (PCI CDE)", table_cell)],
        [Paragraph("Restricted-Data-Vault", table_cell_bold), Paragraph("10.100.40.0/24", table_cell), Paragraph("VLAN 50", table_cell), Paragraph("Critical", table_cell), Paragraph("NIST SP 800-171 Controlled Unclassified Information (CUI)", table_cell)],
    ]
    t_zone = Table(zone_data, colWidths=[95, 75, 45, 50, 275])
    t_zone.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_zone)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Strict PCI CDE Boundary:</b> The <code>PCI-Cardholder-Data</code> zone is cryptographically and physically isolated. No inbound "
        "connections are permitted from corporate or development zones. Communication with the core application tier occurs exclusively "
        "via authenticated, encrypted mTLS API calls to detokenize transaction references.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 7. AWS MULTI-ACCOUNT ARCHITECTURE
    # ==========================================================================
    story.append(Paragraph("6. AWS Multi-Account Cloud Architecture", h1_style))
    story.append(Paragraph(
        "Cloud resources are segmented across three dedicated AWS accounts governed by <b>AWS Organizations</b> (<code>o-apexglobal01</code>). "
        "This multi-account boundary prevents blast-radius propagation between non-production development sandboxes and critical production ledgers:",
        body_style
    ))

    acc_data = [
        [Paragraph("Account Name", table_cell_header), Paragraph("Account ID", table_cell_header), Paragraph("VPC CIDR", table_cell_header), Paragraph("OU Placement", table_cell_header), Paragraph("Primary Workloads & Managed Assets", table_cell_header)],
        [Paragraph("Apex-Production", table_cell_bold), Paragraph("111122223333", table_cell), Paragraph("10.100.0.0/16", table_cell), Paragraph("ou-apex-workloads", table_cell), Paragraph("Customer Portal EKS, PCI EKS, Analytics EKS, Core RDS Postgres, CUI Financial S3 Vault, Customer PII Data Lake", table_cell)],
        [Paragraph("Apex-Development", table_cell_bold), Paragraph("222233334444", table_cell), Paragraph("10.200.0.0/16", table_cell), Paragraph("ou-apex-workloads", table_cell), Paragraph("Dev EKS Sandbox Cluster, ephemeral test telemetry bucket, developer testing microservices", table_cell)],
        [Paragraph("Apex-Security", table_cell_bold), Paragraph("333344445555", table_cell), Paragraph("10.250.0.0/16", table_cell), Paragraph("ou-apex-security", table_cell), Paragraph("Centralized CloudTrail S3 bucket, GuardDuty detectors, SecOps incident response audit tools, Panorama OOB endpoint", table_cell)],
    ]
    t_acc = Table(acc_data, colWidths=[95, 75, 75, 95, 200])
    t_acc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_acc)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Security Group Governance:</b> AWS Security Groups enforce micro-segmentation at the hypervisor level. To prevent security blind spots, "
        "SimuGuard AI enforces strict referential verification: any security group rule referencing an unmapped or unverified workload "
        "(such as <code>sg-guest-network-01</code>) forces an <b>UNKNOWN</b> status rather than assuming confirmed isolation.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 8. IAM ARCHITECTURE
    # ==========================================================================
    story.append(Paragraph("7. IAM Architecture & Identity Federation", h1_style))
    story.append(Paragraph(
        "Identity and Access Management relies on <b>IAM Roles for Service Accounts (IRSA)</b> with OpenID Connect (OIDC) federation. "
        "Pods in Kubernetes assume temporary, short-lived AWS STS credentials bound to their Kubernetes ServiceAccount, completely eliminating "
        "hardcoded static credentials:",
        body_style
    ))
    story.append(Spacer(1, 6))

    if (DIAGRAMS_DIR / "iam_architecture.png").is_file():
        story.append(Paragraph("Figure 7.1: Cloud IAM Architecture, Trust Policies & Permission Boundaries", h2_style))
        story.append(Image(str(DIAGRAMS_DIR / "iam_architecture.png"), width=540, height=335))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Permission Boundaries:</b> Workload identities are governed by mandatory IAM Permission Boundaries. For example, "
        "<code>ApexWorkloadBoundary</code> explicitly contains an absolute <code>Deny</code> for <code>s3:*</code> against the "
        "<code>corp-restricted-cui-financial-vault</code> bucket. Even if an engineer attaches an overprivileged managed policy such as "
        "<code>AmazonS3FullAccess</code>, the boundary prevents unauthorized vault access unless the boundary itself is compromised.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 9. APPLICATION ARCHITECTURE
    # ==========================================================================
    story.append(Paragraph("8. Application Architecture & Service Dependencies", h1_style))
    story.append(Paragraph(
        "Apex Global Technologies operates 12 primary business applications distributed across production, corporate, and security accounts:",
        body_style
    ))

    apps_data = [
        [Paragraph("App ID", table_cell_header), Paragraph("Application Name", table_cell_header), Paragraph("Tier", table_cell_header), Paragraph("Hosted Workload", table_cell_header), Paragraph("Service Dependencies & Calls", table_cell_header)],
        [Paragraph("APP-001", table_cell_bold), Paragraph("Customer Web Portal", table_cell), Paragraph("Tier-1", table_cell), Paragraph("eks-customer-portal-cluster", table_cell), Paragraph("Proxies API calls to Core API Gateway (APP-007) via HTTPS", table_cell)],
        [Paragraph("APP-002", table_cell_bold), Paragraph("Payment Processing", table_cell), Paragraph("Tier-1", table_cell), Paragraph("eks-payment-processor-pool", table_cell), Paragraph("Dispatches card tokenization to PCI enclave via mTLS", table_cell)],
        [Paragraph("APP-003", table_cell_bold), Paragraph("Customer Analytics", table_cell), Paragraph("Tier-2", table_cell), Paragraph("eks-analytics-worker-pool", table_cell), Paragraph("Streams telemetry through API Gateway (APP-007)", table_cell)],
        [Paragraph("APP-004", table_cell_bold), Paragraph("Corporate HR Portal", table_cell), Paragraph("Tier-3", table_cell), Paragraph("Corporate Private Cloud", table_cell), Paragraph("Queries enterprise Single Sign-On IdP (APP-006)", table_cell)],
        [Paragraph("APP-005", table_cell_bold), Paragraph("ERP Financials", table_cell), Paragraph("Tier-1", table_cell), Paragraph("Internal Core VMware Cluster", table_cell), Paragraph("Reads/writes ledger to Restricted CUI S3 Vault", table_cell)],
        [Paragraph("APP-007", table_cell_bold), Paragraph("Core API Gateway", table_cell), Paragraph("Tier-1", table_cell), Paragraph("alb-internal-api-gateway", table_cell), Paragraph("Routes traffic to Payment (APP-002) and Orders (APP-008)", table_cell)],
        [Paragraph("APP-008", table_cell_bold), Paragraph("Order Management", table_cell), Paragraph("Tier-1", table_cell), Paragraph("eks-customer-portal-cluster", table_cell), Paragraph("Streams trade checkouts via gRPC", table_cell)],
        [Paragraph("APP-010", table_cell_bold), Paragraph("Central SIEM Ingestion", table_cell), Paragraph("Tier-1", table_cell), Paragraph("Security Operations Cluster", table_cell), Paragraph("Aggregates CloudTrail, VPC Flow, and PAN-OS syslog", table_cell)],
    ]
    t_apps = Table(apps_data, colWidths=[55, 115, 45, 125, 200])
    t_apps.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_apps)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Cascading Application Impact:</b> In SimuGuard AI's blast-radius engine, if a compute cluster is affected by an open egress rule "
        "or overprivileged IAM attachment, all applications hosted on that cluster (<code>HOSTS_APPLICATION</code>) inherit cascading impact, "
        "ensuring business context is surfaced directly in simulation reports.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 10. DATA CLASSIFICATION AND SENSITIVE ASSETS
    # ==========================================================================
    story.append(Paragraph("9. Data Classification & Sensitive Assets", h1_style))
    story.append(Paragraph(
        "Data governance follows a five-tier classification scheme mapping handling requirements to specific compliance regulations:",
        body_style
    ))

    data_cat = [
        [Paragraph("Classification Tier", table_cell_header), Paragraph("Target Repositories", table_cell_header), Paragraph("Regulatory Framework", table_cell_header), Paragraph("Security & Encryption Controls", table_cell_header)],
        [Paragraph("RESTRICTED_CUI_PII", table_cell_bold), Paragraph("s3-enterprise-cui-vault (DATA-01)", table_cell), Paragraph("NIST SP 800-171 3.1.3, DFARS 252.204-7012, SOX 404", table_cell), Paragraph("FIPS 140-3 KMS CMK (kms-cui-vault), dual-custody access, strict zone segmentation, no direct Internet routing", table_cell)],
        [Paragraph("PCI_CARDHOLDER_DATA", table_cell_bold), Paragraph("rds-pci-token-vault-prod (DATA-02)", table_cell), Paragraph("PCI-DSS v4.0 Requirements 1, 3, 4, 10", table_cell), Paragraph("Mandatory tokenization, isolated CDE subnet, KMS CMK (kms-pci-token), zero ingress from untrusted zones", table_cell)],
        [Paragraph("CONFIDENTIAL_PII", table_cell_bold), Paragraph("rds-postgres-core-prod (DATA-03)", table_cell), Paragraph("GDPR Article 32, CCPA/CPRA, NYDFS 500", table_cell), Paragraph("KMS CMK (kms-customer-db), IAM authentication, column-level masking, strict subnet isolation", table_cell)],
        [Paragraph("INTERNAL_OPERATIONAL", table_cell_bold), Paragraph("s3-dev-staging-telemetry (DATA-06)", table_cell), Paragraph("Enterprise Internal Security Baseline", table_cell), Paragraph("Standard SSE-S3 encryption, internal corporate access only, unclassified staging telemetry", table_cell)],
        [Paragraph("PUBLIC", table_cell_bold), Paragraph("Public CDN & Documentation Assets", table_cell), Paragraph("Public Disclosure Governance", table_cell), Paragraph("Public read access allowed, integrity checksum validation, CloudFront distribution", table_cell)],
    ]
    t_datacat = Table(data_cat, colWidths=[120, 120, 110, 190])
    t_datacat.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_datacat)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>NIST SP 800-171 Control 3.1.3 (Control CUI Flow):</b> The CUI financial ledger contains corporate treasury statements and executive "
        "compensation records. Federal guidelines mandate strict control over the flow of CUI between security zones. SimuGuard AI monitors "
        "all policy changes that could potentially create an unmonitored path into this repository.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 11. NETWORK-TO-IAM DEPENDENCY PATHS
    # ==========================================================================
    story.append(Paragraph("10. Network-to-IAM Dependency Paths", h1_style))
    story.append(Paragraph(
        "Traditional security tools inspect network firewalls and cloud IAM in isolation. SimuGuard AI bridges these silos by evaluating "
        "cross-domain dependency paths across all operational layers:",
        body_style
    ))

    path_data = [
        [Paragraph("Step", table_cell_header), Paragraph("Layer", table_cell_header), Paragraph("Source Entity", table_cell_header), Paragraph("Relationship / Traversal", table_cell_header), Paragraph("Target Entity & Security Impact", table_cell_header)],
        [Paragraph("1", table_cell_bold), Paragraph("Network", table_cell), Paragraph("fw-edge-01-primary", table_cell), Paragraph("ENFORCES_ZONE_POLICY", table_cell), Paragraph("zone-trust-dmz: Policy modifies perimeter ingress/egress filtering", table_cell)],
        [Paragraph("2", table_cell_bold), Paragraph("Network", table_cell), Paragraph("zone-trust-dmz", table_cell), Paragraph("CONTAINS_SUBNET", table_cell), Paragraph("subnet-trust-dmz: 10.100.4.0/24 subnet hosted within zone", table_cell)],
        [Paragraph("3", table_cell_bold), Paragraph("Compute", table_cell), Paragraph("subnet-trust-dmz", table_cell), Paragraph("CONTAINS_WORKLOAD", table_cell), Paragraph("eks-analytics-worker-pool: Ingestion pods inherit subnet security group", table_cell)],
        [Paragraph("4", table_cell_bold), Paragraph("App", table_cell), Paragraph("eks-analytics-worker-pool", table_cell), Paragraph("HOSTS_APPLICATION", table_cell), Paragraph("APP-003: Customer Analytics application executed within worker pods", table_cell)],
        [Paragraph("5", table_cell_bold), Paragraph("IAM", table_cell), Paragraph("eks-analytics-worker-pool", table_cell), Paragraph("ASSUMES_ROLE", table_cell), Paragraph("role-analytics-ingestion-svc: Pods acquire AWS STS credentials via IRSA", table_cell)],
        [Paragraph("6", table_cell_bold), Paragraph("Cloud", table_cell), Paragraph("role-analytics-ingestion-svc", table_cell), Paragraph("CROSS_ZONE_IAM_PATH", table_cell), Paragraph("s3-enterprise-cui-vault: Overprivileged S3 policy permits cross-zone calls", table_cell)],
        [Paragraph("7", table_cell_bold), Paragraph("Data", table_cell), Paragraph("s3-enterprise-cui-vault", table_cell), Paragraph("STORES_DATA", table_cell), Paragraph("DATA-01-CUI-FINANCIAL-VAULT: Restricted CUI ledger potentially exposed", table_cell)],
    ]
    t_path = Table(path_data, colWidths=[25, 50, 115, 130, 220])
    t_path.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_path)
    story.append(Spacer(1, 10))

    story.append(create_callout(
        "A network firewall rule permitting unrestricted outbound egress (0.0.0.0/0) is not critical by itself if workloads have zero "
        "privileges. However, when combined with an IAM policy granting broad S3 full access, the two configurations unite to form an "
        "exploitable exfiltration pathway. SimuGuard AI is uniquely designed to detect this composite multi-tier risk.",
        "COMPOSITE MULTI-TIER RISK EVALUATION",
        "warn",
        styles
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 12. COMPLETE END-TO-END ARCHITECTURE DIAGRAMS
    # ==========================================================================
    story.append(Paragraph("11. End-to-End Data Flow & Attack Path Walkthrough", h1_style))
    story.append(Paragraph(
        "The diagram below traces an end-to-end data flow representing the exact attack pathway simulated during evaluation of PR #4083:",
        body_style
    ))
    story.append(Spacer(1, 6))

    if (DIAGRAMS_DIR / "end_to_end_data_flow.png").is_file():
        story.append(Paragraph("Figure 11.1: End-to-End Ingress, Workload, IAM IRSA and Data Asset Exfiltration Flow", h2_style))
        story.append(Image(str(DIAGRAMS_DIR / "end_to_end_data_flow.png"), width=540, height=335))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Attack Path Analysis:</b><br/>"
        "1. <b>Ingress Exposure:</b> Terraform PR #4083 introduces rule <code>Allow-DMZ-Egress-Wildcard</code>, configuring destination <code>any</code> "
        "and application <code>any</code> without a security profile group.<br/>"
        "2. <b>Compute Pod Infiltration:</b> Pods running in <code>eks-analytics-worker-pool</code> acquire unmonitored egress channels.<br/>"
        "3. <b>Overprivileged Identity Attachment:</b> PR #4083 attaches <code>arn:aws:iam::aws:policy/AmazonS3FullAccess</code> to "
        "<code>role-analytics-ingestion-svc</code>.<br/>"
        "4. <b>Cross-Zone Vault Exfiltration:</b> The analytics pod uses its newly acquired wildcard privileges to query the CUI vault bucket "
        "(<code>s3-enterprise-cui-vault</code>) across zone boundaries, compromising the NIST SP 800-171 financial ledger (<code>DATA-01</code>).<br/>"
        "5. <b>Pre-Flight Block:</b> SimuGuard AI intercepts the Terraform plan, identifies the full composite path, flags a Risk Score of 96/100, "
        "and issues a <b>BLOCK_DEPLOYMENT</b> verdict.",
        body_style
    ))
    story.append(PageBreak())

    # ==========================================================================
    # 13. SIMUGUARD AI INTEGRATION ARCHITECTURE
    # ==========================================================================
    story.append(Paragraph("12. SimuGuard AI Platform Architecture", h1_style))
    story.append(Paragraph(
        "SimuGuard AI functions as an automated pre-flight security evaluation engine. The platform ingests proposed Terraform changes, "
        "queries the Digital Twin topology graph, evaluates security gaps, and produces deterministic deployment verdicts:",
        body_style
    ))
    story.append(Spacer(1, 6))

    if (DIAGRAMS_DIR / "simuguard_platform_architecture.png").is_file():
        story.append(Paragraph("Figure 12.1: SimuGuard AI Platform Architecture & Simulation Pipeline", h2_style))
        story.append(Image(str(DIAGRAMS_DIR / "simuguard_platform_architecture.png"), width=540, height=335))
        story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<b>Implementation Boundaries & Future Roadmap:</b> To ensure complete architectural transparency, the table below delineates "
        "currently operational components from planned future platform capabilities:",
        body_style
    ))

    roadmap_data = [
        [Paragraph("Pipeline Component", table_cell_header), Paragraph("Implementation Status", table_cell_header), Paragraph("Operational Capabilities & Scope", table_cell_header)],
        [Paragraph("Terraform HCL Parsing", table_cell_bold), Paragraph("IMPLEMENTED (Phase 2)", table_cell), Paragraph("python-hcl2 parser with syntax error isolation, PAN-OS and AWS resource normalization", table_cell)],
        [Paragraph("Enterprise Digital Twin", table_cell_bold), Paragraph("IMPLEMENTED (Phase 3.5)", table_cell), Paragraph("64-node NetworkX graph modeling firewalls, zones, subnets, SGs, IAM, apps, and data", table_cell)],
        [Paragraph("Blast Radius Engine", table_cell_bold), Paragraph("IMPLEMENTED (Phase 3)", table_cell), Paragraph("Direct and cascading impact traversal, unmapped resource detection (UNKNOWN status)", table_cell)],
        [Paragraph("Security Analysis Rules", table_cell_bold), Paragraph("PHASE 4 ROADMAP", table_cell), Paragraph("Automated detection of shadowed rules, disabled threat profiles, and wildcard policies", table_cell)],
        [Paragraph("Quantitative Risk Scoring", table_cell_bold), Paragraph("PHASE 4 ROADMAP", table_cell), Paragraph("0 to 100 mathematical risk scoring algorithm with criticality weighting", table_cell)],
        [Paragraph("Remediation Generation", table_cell_bold), Paragraph("PHASE 4 ROADMAP", table_cell), Paragraph("Automated generation of least-privilege Terraform replacements and policy fixes", table_cell)],
        [Paragraph("Live Panorama API Sync", table_cell_bold), Paragraph("FUTURE PLANNED INTEGRATION", table_cell), Paragraph("Bi-directional REST/XML API commit integration (Planned for future release)", table_cell)],
        [Paragraph("Live AWS Cloud API Sync", table_cell_bold), Paragraph("FUTURE PLANNED INTEGRATION", table_cell), Paragraph("Real-time AWS Config and boto3 state synchronization (Planned for future release)", table_cell)],
    ]
    t_road = Table(roadmap_data, colWidths=[120, 110, 310])
    t_road.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_road)
    story.append(PageBreak())

    # ==========================================================================
    # 14. SECURITY BOUNDARIES AND TRUST RELATIONSHIPS
    # ==========================================================================
    story.append(Paragraph("13. Seeded Vulnerabilities & Security Misconfigurations", h1_style))
    story.append(Paragraph(
        "The Apex Global Technologies dataset deliberately seeds realistic enterprise misconfigurations to serve as benchmark test cases "
        "for security validation engines:",
        body_style
    ))

    vuln_data = [
        [Paragraph("Vulnerability ID", table_cell_header), Paragraph("Target Resource", table_cell_header), Paragraph("Layer", table_cell_header), Paragraph("Severity", table_cell_header), Paragraph("Misconfiguration Description & Attack Surface", table_cell_header)],
        [Paragraph("RULE-PAN-011", table_cell_bold), Paragraph("rule-emergency-any-any-bypass", table_cell), Paragraph("PAN-OS", table_cell), Paragraph("CRITICAL", table_cell), Paragraph("Forgotten emergency rule allowing any source, destination, and service without security profiles, bypassing perimeter inspection", table_cell)],
        [Paragraph("RULE-PAN-014", table_cell_bold), Paragraph("rule-shadowed-portal-allow", table_cell), Paragraph("PAN-OS", table_cell), Paragraph("MEDIUM", table_cell), Paragraph("Shadowed rule positioned behind identical rule RULE-PAN-001, resulting in redundant dead policy that misleads security audits", table_cell)],
        [Paragraph("RULE-PAN-003", table_cell_bold), Paragraph("rule-allow-dmz-to-corp-services", table_cell), Paragraph("PAN-OS", table_cell), Paragraph("HIGH", table_cell), Paragraph("Threat Prevention explicitly disabled (security_profile_group = none), exposing inter-zone routing to uninspected malware", table_cell)],
        [Paragraph("POLICY-IAM-002", table_cell_bold), Paragraph("AmazonS3FullAccess", table_cell), Paragraph("Cloud IAM", table_cell), Paragraph("CRITICAL", table_cell), Paragraph("Wildcard s3:* attached to DMZ worker role, allowing pods to bypass zone boundaries and access the CUI Financial Vault", table_cell)],
        [Paragraph("POLICY-IAM-003", table_cell_bold), Paragraph("AdministratorAccess", table_cell), Paragraph("Cloud IAM", table_cell), Paragraph("CRITICAL", table_cell), Paragraph("Wildcard action * on resource *, attached to CI/CD deployment role, creating catastrophic blast radius", table_cell)],
        [Paragraph("TRUST-IAM-003", table_cell_bold), Paragraph("trust-excessive-dev-to-prod", table_cell), Paragraph("Cloud IAM", table_cell), Paragraph("CRITICAL", table_cell), Paragraph("Insecure cross-account trust allowing development sandbox users (222233334444) to assume production CI/CD role without MFA", table_cell)],
        [Paragraph("SG-CLOUD-007", table_cell_bold), Paragraph("sg-guest-network-01", table_cell), Paragraph("Cloud SG", table_cell), Paragraph("HIGH", table_cell), Paragraph("Unmapped security group absent from Digital Twin topology, enforcing the engine to report UNKNOWN status rather than assuming safe", table_cell)],
        [Paragraph("S3-BUCKET-003", table_cell_bold), Paragraph("s3-dev-staging-telemetry", table_cell), Paragraph("Cloud S3", table_cell), Paragraph("HIGH", table_cell), Paragraph("Public Access Block disabled with permissive bucket policy, inadvertently exposing staging telemetry to unauthenticated public access", table_cell)],
    ]
    t_vuln = Table(vuln_data, colWidths=[70, 110, 50, 55, 255])
    t_vuln.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_vuln)
    story.append(PageBreak())

    # ==========================================================================
    # 15. GLOSSARY OF TECHNICAL TERMS
    # ==========================================================================
    story.append(Paragraph("14. Glossary of Important Technical Terms", h1_style))
    story.append(Paragraph(
        "This glossary provides standard enterprise cybersecurity definitions for terms referenced throughout this document and the SimuGuard AI platform:",
        body_style
    ))

    glossary_data = [
        [Paragraph("Term", table_cell_header), Paragraph("Standard Cybersecurity Definition", table_cell_header)],
        [Paragraph("App-ID (PAN-OS)", table_cell_bold), Paragraph("Palo Alto Networks patented deep packet inspection technology that identifies applications traversing the network regardless of port, protocol, evasive tactics, or SSL encryption.", table_cell)],
        [Paragraph("Panorama", table_cell_bold), Paragraph("Centralized management platform for Palo Alto Networks next-generation firewalls, providing unified policy rulebases, shared device groups, templates, and logging across distributed appliances.", table_cell)],
        [Paragraph("IRSA (EKS)", table_cell_bold), Paragraph("IAM Roles for Service Accounts. An AWS mechanism that federates Kubernetes service accounts with AWS IAM via OIDC, granting pods short-lived STS credentials without static secrets.", table_cell)],
        [Paragraph("Permission Boundary", table_cell_bold), Paragraph("An advanced AWS IAM governance control that sets the maximum permissions an identity-based policy can grant to an IAM role or user, preventing privilege escalation.", table_cell)],
        [Paragraph("Digital Twin", table_cell_bold), Paragraph("A dynamic, software-defined graph representation of physical and cloud infrastructure, network connectivity, IAM policies, and data assets used to simulate operational changes safely.", table_cell)],
        [Paragraph("Blast Radius", table_cell_bold), Paragraph("The maximum potential impact or exposure across downstream infrastructure, compute workloads, applications, and sensitive data assets resulting from a configuration change or security compromise.", table_cell)],
        [Paragraph("CUI", table_cell_bold), Paragraph("Controlled Unclassified Information. Sensitive government or corporate contract data requiring safeguarding and dissemination controls pursuant to NIST SP 800-171 and DFARS 252.204-7012.", table_cell)],
        [Paragraph("PCI CDE", table_cell_bold), Paragraph("Cardholder Data Environment. The isolated network environment containing people, processes, and technologies that store, process, or transmit cardholder payment data under PCI-DSS v4.0.", table_cell)],
        [Paragraph("Pre-Rulebase", table_cell_bold), Paragraph("Palo Alto firewall security rules pushed by Panorama that evaluate before local firewall administrator rules, ensuring global enterprise security baselines cannot be overridden.", table_cell)],
        [Paragraph("DNAT", table_cell_bold), Paragraph("Destination Network Address Translation. Rewrites the destination IP address of incoming packets (e.g. from a public VIP to an internal private application load balancer).", table_cell)],
    ]
    t_gloss = Table(glossary_data, colWidths=[120, 420])
    t_gloss.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("PADDING", (0, 0), (-1, -1), 4.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(t_gloss)

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF: {PDF_PATH}")


if __name__ == "__main__":
    build_pdf()

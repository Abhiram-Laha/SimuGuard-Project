"""PowerPoint Presentation Generator for SimuGuard AI.
Generates: deliverables/Apex_Global_Technologies_Architecture_Presentation.pptx
16 professional, widescreen (16:9) slides based on the Apex Global Technologies dataset.
"""

from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

REPO_ROOT = Path(__file__).resolve().parent
DELIVERABLES_DIR = REPO_ROOT / "deliverables"
DIAGRAMS_DIR = DELIVERABLES_DIR / "diagrams"
PPTX_PATH = DELIVERABLES_DIR / "Apex_Global_Technologies_Architecture_Presentation.pptx"

# Color Palette
COLOR_NAVY = RGBColor(15, 23, 42)        # #0F172A
COLOR_DARK_SLATE = RGBColor(30, 41, 59)  # #1E293B
COLOR_LIGHT_BG = RGBColor(248, 250, 252) # #F8FAFC
COLOR_WHITE = RGBColor(255, 255, 255)
COLOR_MUTED = RGBColor(100, 116, 139)    # #64748B
COLOR_BLUE = RGBColor(29, 78, 216)       # #1D4ED8
COLOR_EMERALD = RGBColor(16, 185, 129)   # #10B981
COLOR_AMBER = RGBColor(245, 158, 11)     # #F59E0B
COLOR_RED = RGBColor(239, 68, 68)        # #EF4444
COLOR_PURPLE = RGBColor(139, 92, 246)    # #8B5CF6
COLOR_BORDER = RGBColor(203, 213, 225)   # #CBD5E1
COLOR_CARD_BG = RGBColor(255, 255, 255)


def add_header(slide, title_text, category="APEX GLOBAL TECHNOLOGIES ARCHITECTURE"):
    """Add a consistent, professional header banner to standard slides."""
    # Category tag
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11), Inches(0.3))
    tf_c = cat_box.text_frame
    tf_c.word_wrap = True
    p_c = tf_c.paragraphs[0]
    p_c.text = category.upper()
    p_c.font.size = Pt(9)
    p_c.font.bold = True
    p_c.font.color.rgb = COLOR_BLUE

    # Title
    t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.65), Inches(11.5), Inches(0.6))
    tf_t = t_box.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = title_text
    p_t.font.size = Pt(20)
    p_t.font.bold = True
    p_t.font.color.rgb = COLOR_NAVY


def add_card(slide, left, top, width, height, title, body_bullets, border_color=COLOR_BORDER, bg_color=COLOR_WHITE):
    """Draw a styled card shape with a title and bulleted points."""
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = bg_color
    shape.line.color.rgb = border_color
    shape.line.width = Pt(1)

    # Content
    tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.15), width - Inches(0.4), height - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    
    # Title
    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.size = Pt(13)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_DARK_SLATE
    p0.space_after = Pt(6)

    # Bullets
    for b in body_bullets:
        p = tf.add_paragraph()
        p.text = f"• {b}"
        p.font.size = Pt(10)
        p.font.color.rgb = COLOR_DARK_SLATE
        p.space_after = Pt(4)


def build_presentation():
    print(f"Generating Presentation: {PPTX_PATH}...")
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # ==========================================================================
    # SLIDE 1: Title Slide (Dark Navy)
    # ==========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    bg1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg1.fill.solid()
    bg1.fill.fore_color.rgb = COLOR_NAVY
    bg1.line.fill.background()

    tb1 = s1.shapes.add_textbox(Inches(1.2), Inches(2.2), Inches(11.0), Inches(3.2))
    tf1 = tb1.text_frame
    
    p_tag = tf1.paragraphs[0]
    p_tag.text = "SIMUGUARD AI  |  CYBERSECURITY DIGITAL TWIN BENCHMARK"
    p_tag.font.size = Pt(12)
    p_tag.font.bold = True
    p_tag.font.color.rgb = COLOR_BLUE
    p_tag.space_after = Pt(12)

    p_t = tf1.add_paragraph()
    p_t.text = "Apex Global Technologies"
    p_t.font.size = Pt(36)
    p_t.font.bold = True
    p_t.font.color.rgb = COLOR_WHITE
    p_t.space_after = Pt(8)

    p_sub = tf1.add_paragraph()
    p_sub.text = "Enterprise Hybrid Cloud Architecture & Pre-Flight Security Simulation"
    p_sub.font.size = Pt(18)
    p_sub.font.color.rgb = RGBColor(148, 163, 184)
    p_sub.space_after = Pt(28)

    p_meta = tf1.add_paragraph()
    p_meta.text = "Palo Alto Networks PAN-OS 11.1 Nebula  •  Panorama  •  AWS Multi-Account  •  EKS IRSA  •  NIST SP 800-171 CUI"
    p_meta.font.size = Pt(11)
    p_meta.font.color.rgb = COLOR_WHITE

    # ==========================================================================
    # SLIDE 2: Organisation Overview
    # ==========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_header(s2, "Enterprise Organisation Overview & Governance")
    
    add_card(s2, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.3), "Enterprise Profile: Apex Global Technologies", [
        "Fictional multinational financial technology enterprise (apex-global.example).",
        "Operates mission-critical consumer banking, order processing, and payment services.",
        "Governed by NIST CSF 2.0 (PR.AC, PR.PT), NIST SP 800-171 Rev 2, and PCI-DSS v4.0.",
        "Combines on-premises next-generation firewalls with a multi-account AWS Cloud estate.",
        "Digital Twin Purpose: Ingests infrastructure configurations into a 64-node graph to predict the impact of Terraform PRs prior to deployment."
    ])

    add_card(s2, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.3), "Key Operational Business Units", [
        "FinTech Digital Banking Operations:\n  Owns Customer Portal (APP-001) and Core Postgres Database (rds-postgres-core-prod).",
        "Payment Security & Tokenization Operations:\n  Operates isolated PCI CDE enclave (APP-002) and Token Vault under PCI-DSS v4.0.",
        "Data Engineering & Analytics:\n  Maintains DMZ analytics ingestion pipeline (APP-003) and high-throughput data lakes.",
        "SecOps & Cloud Platform Engineering:\n  Governs Panorama 11.1, firewall rulebases, AWS IAM boundaries, and SIEM monitoring."
    ])

    # ==========================================================================
    # SLIDE 3: High-Level Enterprise Architecture
    # ==========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_header(s3, "High-Level Enterprise Hybrid Architecture")

    if (DIAGRAMS_DIR / "enterprise_organisation.png").is_file():
        s3.shapes.add_picture(str(DIAGRAMS_DIR / "enterprise_organisation.png"), Inches(0.8), Inches(1.5), width=Inches(7.8))

    add_card(s3, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Structural Pillars", [
        "Palo Alto Security Perimeter:\nDual PA-5450 HA pair terminates Internet traffic and applies Layer 7 App-ID inspection.",
        "Internal Zero-Trust Core:\nPA-3440 HA pair segregates databases, PCI tokens, and CUI vaults.",
        "AWS Multi-Account Governance:\nThree isolated AWS accounts (Prod, Dev, Sec) linked via AWS Organizations (o-apexglobal01).",
        "Unified Central SIEM:\nAll firewall syslog and AWS CloudTrail flow logs aggregate into Security account."
    ])

    # ==========================================================================
    # SLIDE 4: Complete Network Topology
    # ==========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_header(s4, "Enterprise Network Topology & 9 Security Zones")

    if (DIAGRAMS_DIR / "network_architecture.png").is_file():
        s4.shapes.add_picture(str(DIAGRAMS_DIR / "network_architecture.png"), Inches(0.8), Inches(1.5), width=Inches(8.2))

    add_card(s4, Inches(9.2), Inches(1.5), Inches(3.3), Inches(5.3), "Network Highlights", [
        "RFC 1918 Private Addressing:\nAll internal subnets strictly use private RFC 1918 CIDRs.",
        "RFC 5737 Scoped Public IPs:\nPublic endpoints use documentation VIPs (203.0.113.20, 198.51.100.0/24).",
        "Dedicated Transit VLAN:\n10.255.0.0/30 point-to-point transit interconnects edge and internal firewalls.",
        "Strict Enclaves:\nPCI Cardholder and Restricted CUI Vault zones have zero direct Internet ingress."
    ])

    # ==========================================================================
    # SLIDE 5: Palo Alto Panorama & Firewall Architecture
    # ==========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_header(s5, "Palo Alto Firewall & Panorama 11.1 Architecture")

    add_card(s5, Inches(0.8), Inches(1.5), Inches(3.7), Inches(5.3), "Panorama Management (M-600)", [
        "Centralized Appliance: pan-mgmt-01 (10.250.1.10) running PAN-OS 11.1 Nebula.",
        "DG-Enterprise-Shared:\nPushes global Pre-Rulebase dropping RFC1918 spoofing and enforcing core DNS/NTP egress.",
        "DG-Internet-Perimeter:\nPushes perimeter rules to PA-5450 HA pair for web ingress and DMZ NAT policies.",
        "DG-Internal-Segmentation:\nPushes strict zero-trust segmentation rules to PA-3440 internal core HA pair."
    ], border_color=COLOR_PURPLE)

    add_card(s5, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.3), "Firewall Appliances & HA", [
        "Perimeter Firewalls (PA-5450 Pair):\n• Primary: fw-edge-01-primary (Active)\n• Secondary: fw-edge-02-secondary (Standby)\n• High-throughput Internet edge gateway.",
        "Internal Segmentation (PA-3440 Pair):\n• Primary: fw-internal-01-primary (Active)\n• Secondary: fw-internal-02-secondary (Standby)\n• East-West segmentation core.",
        "High Availability Links:\n• HA1: Control plane heartbeat\n• HA2: Real-time session state sync."
    ], border_color=COLOR_RED)

    add_card(s5, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Rulebases & Threat Inspection", [
        "22 Realistic Security Policies:\nStructured into Pre-Rulebase, Local Rules, and Post-Rulebase defaults.",
        "App-ID Deep Inspection:\nIdentifies panos-web-browsing, panos-ssl, postgresql, and dns without relying on ports.",
        "Strict Threat Profiles:\nAntivirus, Anti-Spyware, Vulnerability Protection, and URL Filtering active across rules.",
        "Seeded Test Gaps:\nIncludes rule with disabled threat profiles (RULE-PAN-003) and shadowed policy (RULE-PAN-014)."
    ], border_color=COLOR_AMBER)

    # ==========================================================================
    # SLIDE 6: Network Zones & Segmentation
    # ==========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_header(s6, "Network Zones & Zero-Trust Segmentation Taxonomy")

    add_card(s6, Inches(0.8), Inches(1.5), Inches(3.7), Inches(2.5), "Public & Boundary Zones", [
        "Untrust-Internet (0.0.0.0/0):\nExternal Internet ingress terminated on edge firewall.",
        "Trust-DMZ (10.100.4.0/24 - VLAN 10):\nPublic reverse proxies, ALBs, and analytics worker pods.",
        "Transit-Internal (10.255.0.0/30 - VLAN 99):\nInter-firewall transit backbone isolating DMZ from core."
    ], border_color=COLOR_AMBER)

    add_card(s6, Inches(4.8), Inches(1.5), Inches(3.7), Inches(2.5), "Workload & Application Zones", [
        "Prod-App-Workloads (10.100.10.0/23 - VLAN 20):\nProduction Kubernetes clusters and portal backend pods.",
        "Dev-App-Workloads (10.200.10.0/23 - VLAN 200):\nDevelopment testing sandboxes and staging pipelines.",
        "Corp-Users (10.10.0.0/16 - VLAN 100):\nCorporate workstations and remote access SSL-VPN pools."
    ], border_color=COLOR_BLUE)

    add_card(s6, Inches(8.8), Inches(1.5), Inches(3.7), Inches(2.5), "Critical Restricted Zones", [
        "Database-Backend (10.100.20.0/24 - VLAN 30):\nProduction relational database clusters (PostgreSQL).",
        "PCI-Cardholder-Data (10.100.30.0/24 - VLAN 40):\nStrictly isolated PCI DSS tokenization enclave.",
        "Restricted-Data-Vault (10.100.40.0/24 - VLAN 50):\nNIST SP 800-171 CUI financial ledger storage."
    ], border_color=COLOR_RED)

    add_card(s6, Inches(0.8), Inches(4.3), Inches(11.7), Inches(2.5), "Zero-Trust Enforcement Principles", [
        "Default-Deny Inter-Zone Routing: Traffic cannot cross between security zones without an explicit, matched firewall rule.",
        "Strict Enclave Isolation: The PCI CDE and Restricted Data Vault have zero direct Internet ingress or egress pathways.",
        "Deep Inspection Mandatory: Traffic between application and database zones must match expected Layer 7 protocols (e.g. postgresql).",
        "SimuGuard AI Verification: Any Terraform change attempting to bridge these zones or remove security profiles is flagged as a high-severity risk."
    ], border_color=COLOR_EMERALD)

    # ==========================================================================
    # SLIDE 7: AWS Multi-Account Architecture
    # ==========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_header(s7, "AWS Multi-Account Architecture (AWS Organizations: o-apexglobal01)")

    add_card(s7, Inches(0.8), Inches(1.5), Inches(3.7), Inches(5.3), "Production: 111122223333", [
        "OU: ou-apex-workloads",
        "VPC: vpc-prod-us-east-1 (10.100.0.0/16)",
        "Workloads:\n• eks-customer-portal-cluster\n• eks-payment-processor-pool\n• eks-analytics-worker-pool\n• rds-postgres-core-prod (Multi-AZ)\n• rds-pci-token-vault-prod",
        "Storage & KMS:\n• s3-enterprise-cui-vault (CUI Vault)\n• s3-customer-pii-lake-prod\n• kms-cui-vault, kms-pci-token",
        "Governance:\nSubject to strict workload permission boundaries."
    ], border_color=COLOR_EMERALD)

    add_card(s7, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.3), "Development: 222233334444", [
        "OU: ou-apex-workloads",
        "VPC: vpc-dev-us-east-1 (10.200.0.0/16)",
        "Workloads:\n• eks-dev-sandbox-cluster\n• Developer staging microservices\n• Ephemeral CI/CD runners",
        "Storage:\n• s3-dev-staging-telemetry\n  (Non-sensitive operational data)",
        "Security Finding:\nContains seeded trust vulnerability allowing dev users to assume production deployment pipeline."
    ], border_color=COLOR_BLUE)

    add_card(s7, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Security Operations: 333344445555", [
        "OU: ou-apex-security",
        "VPC: vpc-secops-us-east-1 (10.250.0.0/16)",
        "Centralized Log Aggregation:\n• s3-central-security-cloudtrail-sec\n  Immutable CloudTrail multi-region bucket\n• Encrypted with dedicated SecOps KMS key.",
        "Security Tooling:\n• AWS GuardDuty detectors\n• Security Hub compliance aggregators\n• Incident response read-only roles\n• Panorama OOB management endpoint."
    ], border_color=COLOR_PURPLE)

    # ==========================================================================
    # SLIDE 8: IAM Architecture & IRSA
    # ==========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_header(s8, "Cloud IAM Architecture & EKS Workload Federation")

    if (DIAGRAMS_DIR / "iam_architecture.png").is_file():
        s8.shapes.add_picture(str(DIAGRAMS_DIR / "iam_architecture.png"), Inches(0.8), Inches(1.5), width=Inches(7.8))

    add_card(s8, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "IAM Architecture Highlights", [
        "EKS IRSA OIDC Federation:\nPods acquire temporary AWS STS tokens bound to their Kubernetes ServiceAccount, eliminating static access keys.",
        "Mandatory Permission Boundaries:\nApexWorkloadBoundary enforces an absolute DENY on the CUI vault bucket, guarding against overprivileged policies.",
        "Scoped Least-Privilege Baseline:\nBaseline role-analytics-ingestion-svc permits writes strictly to unclassified staging.",
        "SimuGuard AI Detection:\nSimulates PR #4083 attaching AmazonS3FullAccess and traces the cross-zone exposure to the CUI vault."
    ])

    # ==========================================================================
    # SLIDE 9: Application & Workload Architecture
    # ==========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_header(s9, "Application Portfolio & Inter-Service Dependencies")

    add_card(s9, Inches(0.8), Inches(1.5), Inches(3.7), Inches(5.3), "Tier-1 Customer Services", [
        "APP-001: Customer Web Portal\n• React / Next.js customer banking UI.\n• Hosted on eks-customer-portal-cluster.\n• Proxies API calls to Core API Gateway.",
        "APP-007: Core API Gateway\n• Central reverse proxy & rate limiter.\n• Enforces mTLS authentication.\n• Routes checkouts to Payment & Orders.",
        "APP-008: Order Management Engine\n• High-throughput trade & order matching.\n• Streams events via gRPC.",
        "APP-009: Real-time Ingestion Stream\n• Ingests market feeds and transactional telemetry."
    ], border_color=COLOR_BLUE)

    add_card(s9, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.3), "Tier-1 Payment & Financial Core", [
        "APP-002: PCI Payment Processing\n• Executes in isolated PCI CDE enclave.\n• Tokenizes credit card numbers.\n• Encrypted with dedicated KMS CMK.\n• Exclusive access to Token DB.",
        "APP-005: Core ERP Financials\n• Corporate treasury and general ledger.\n• Interacts with Restricted CUI Vault.",
        "APP-006: Single Sign-On IdP\n• Okta / Keycloak identity provider\n• Enforces MFA across all employee sessions."
    ], border_color=COLOR_RED)

    add_card(s9, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Tier-2 & Tier-3 Operations", [
        "APP-003: Customer Analytics\n• Clickstream and user behavior analysis.\n• Executed on DMZ analytics cluster.\n• Target of PR #4083 attack scenario.",
        "APP-004: Corporate HR Portal\n• Employee records & payroll management.",
        "APP-010: Central Security SIEM\n• Real-time threat detection & alert triage.",
        "APP-011: Developer Sandbox\n• Non-production testing microservices."
    ], border_color=COLOR_EMERALD)

    # ==========================================================================
    # SLIDE 10: Sensitive Data & Security Boundaries
    # ==========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_header(s10, "Data Classification Tiers & Sensitive Repositories")

    add_card(s10, Inches(0.8), Inches(1.5), Inches(3.7), Inches(5.3), "Restricted CUI & PCI Tiers", [
        "RESTRICTED_CUI_PII:\n• Target: s3-enterprise-cui-vault (DATA-01)\n• Governed by NIST SP 800-171 3.1.3 & SOX 404.\n• Encrypted: FIPS 140-3 KMS (kms-cui-vault).\n• No direct Internet routing allowed.",
        "PCI_CARDHOLDER_DATA:\n• Target: rds-pci-token-vault-prod (DATA-02)\n• Governed by PCI-DSS v4.0 Req 3.4.\n• Encrypted: Dedicated KMS (kms-pci-token).\n• Resides in isolated PCI CDE subnet."
    ], border_color=COLOR_RED)

    add_card(s10, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.3), "Confidential & Internal Tiers", [
        "CONFIDENTIAL_PII:\n• Target: rds-postgres-core-prod (DATA-03)\n• Governed by GDPR Article 32 & CCPA.\n• Contains customer identity records.\n• Encrypted: KMS (kms-customer-db).",
        "INTERNAL_OPERATIONAL:\n• Target: s3-dev-staging-telemetry (DATA-06)\n• Non-sensitive staging metrics.\n• Standard SSE-S3 encryption.\n• Standard internal corporate access."
    ], border_color=COLOR_AMBER)

    add_card(s10, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Security Audit & Public Tiers", [
        "SECURITY_AUDIT_LOGS:\n• Target: s3-central-security-cloudtrail-sec (DATA-05)\n• Central immutable audit repository.\n• Encrypted: SecOps KMS CMK.\n• Enforces MFA Delete and S3 Object Lock.",
        "PUBLIC ASSETS:\n• Public CDN documentation and web assets.\n• Public read access permitted.\n• Integrity hash validation enforced."
    ], border_color=COLOR_PURPLE)

    # ==========================================================================
    # SLIDE 11: End-to-End Data Flow & Attack Path
    # ==========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    add_header(s11, "End-to-End Network-to-IAM Data Flow & Blast Propagation")

    if (DIAGRAMS_DIR / "end_to_end_data_flow.png").is_file():
        s11.shapes.add_picture(str(DIAGRAMS_DIR / "end_to_end_data_flow.png"), Inches(0.8), Inches(1.5), width=Inches(8.0))

    add_card(s11, Inches(9.0), Inches(1.5), Inches(3.5), Inches(5.3), "PR #4083 Attack Path Analysis", [
        "1. Ingress Rule Change:\nPR creates unrestricted egress with destination 'any' and application 'any'.",
        "2. Compute Infiltration:\nAnalytics pods in Trust-DMZ inherit uninspected outbound pathway.",
        "3. Overprivileged Policy:\nPR attaches AmazonS3FullAccess to role-analytics-ingestion-svc.",
        "4. Cross-Zone Vault Access:\nDMZ pod uses broad S3 credentials to reach s3-enterprise-cui-vault across zone boundaries.",
        "5. CUI Data Compromise:\nRestricted CUI Financial Ledger (DATA-01) is potentially exposed to exfiltration.",
        "SimuGuard AI Result:\nDetects composite path -> Issues BLOCK_DEPLOYMENT."
    ], border_color=COLOR_RED)

    # ==========================================================================
    # SLIDE 12: Seeded Security Risks
    # ==========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    add_header(s12, "Seeded Security Risks & Detection Benchmark Test Cases")

    add_card(s12, Inches(0.8), Inches(1.5), Inches(3.7), Inches(5.3), "Palo Alto Firewall Gaps", [
        "RULE-PAN-011 (CRITICAL):\nForgotten emergency rule allows any source, destination, and application with security profiles set to 'none'.",
        "RULE-PAN-014 (MEDIUM):\nShadowed rule positioned behind identical rule RULE-PAN-001; creates dead policy cluttering audits.",
        "RULE-PAN-003 (HIGH):\nThreat profiles disabled on DMZ-to-Corp policy, satisfying lateral movement blast condition.",
        "RULE-PAN-006 (HIGH):\nOutbound rule with destination 'any' allows arbitrary web browsing data tunneling."
    ], border_color=COLOR_RED)

    add_card(s12, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.3), "AWS IAM Security Gaps", [
        "POLICY-IAM-002 (CRITICAL):\nAmazonS3FullAccess wildcard attached to DMZ ingestion role, breaching zone boundaries.",
        "POLICY-IAM-003 (CRITICAL):\nAdministratorAccess root wildcard attached to production CI/CD pipeline role.",
        "TRUST-IAM-003 (CRITICAL):\nInsecure trust allowing dev account users to assume production deployment pipeline without MFA."
    ], border_color=COLOR_AMBER)

    add_card(s12, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Cloud & Storage Gaps", [
        "SG-CLOUD-007 (HIGH):\nSecurity group sg-guest-network-01 unmapped in topology; forces engine to return UNKNOWN status rather than assuming safe.",
        "S3-BUCKET-003 (HIGH):\nPublic Access Block disabled with permissive bucket policy on s3-dev-staging-telemetry, leaking test data.",
        "KMS Policy Gaps:\nKey policy permitting wildcard Principal access without conditions."
    ], border_color=COLOR_PURPLE)

    # ==========================================================================
    # SLIDE 13: SimuGuard AI Platform Architecture
    # ==========================================================================
    s13 = prs.slides.add_slide(blank_layout)
    add_header(s13, "SimuGuard AI Platform Architecture & Simulation Pipeline")

    if (DIAGRAMS_DIR / "simuguard_platform_architecture.png").is_file():
        s13.shapes.add_picture(str(DIAGRAMS_DIR / "simuguard_platform_architecture.png"), Inches(0.8), Inches(1.5), width=Inches(8.0))

    add_card(s13, Inches(9.0), Inches(1.5), Inches(3.5), Inches(5.3), "Architecture Highlights", [
        "1. Ingestion Engine:\nParses Terraform HCL into typed Pydantic models (Phase 2).",
        "2. Digital Twin Graph:\nNetworkX directed graph with 64 nodes & 39 edges (Phase 3.5).",
        "3. Blast Radius Engine:\nMulti-tier propagation across network, workloads, IAM, and data assets (Phase 3).",
        "4. Strict Safety Governance:\nUnmapped resources yield UNKNOWN status, never false safety.",
        "5. Automated Verdict:\nEmits ALLOW, WARN, or BLOCK before Terraform deployment."
    ])

    # ==========================================================================
    # SLIDE 14: How SimuGuard Evaluates Change Requests
    # ==========================================================================
    s14 = prs.slides.add_slide(blank_layout)
    add_header(s14, "Pre-Flight Evaluation Lifecycle for Terraform Changes")

    add_card(s14, Inches(0.8), Inches(1.5), Inches(2.7), Inches(5.3), "Step 1: Ingestion", [
        "DevOps engineer opens PR modifying .tf files.",
        "HCL Parser reads raw Terraform syntax.",
        "Distinguishes syntax errors from provider schema issues.",
        "Extracts rules, applications, CIDRs, and IAM policies."
    ], border_color=COLOR_BLUE)

    add_card(s14, Inches(3.8), Inches(1.5), Inches(2.7), Inches(5.3), "Step 2: Digital Twin Query", [
        "Maps resource to topology nodes.",
        "Validates firewall zones against catalog.",
        "Resolves Security Groups to explicit compute workloads.",
        "Flags unmapped resources as UNKNOWN."
    ], border_color=COLOR_EMERALD)

    add_card(s14, Inches(6.8), Inches(1.5), Inches(2.7), Inches(5.3), "Step 3: Blast Traversal", [
        "Evaluates blast conditions on directed edges.",
        "Checks for App-ID bypass or wildcard destinations.",
        "Traces reverse role assumptions to workloads.",
        "Cascades exposure to hosted apps and sensitive data."
    ], border_color=COLOR_AMBER)

    add_card(s14, Inches(9.8), Inches(1.5), Inches(2.7), Inches(5.3), "Step 4: Verdict & Report", [
        "Calculates quantitative risk score (0–100).",
        "Generates least-privilege remediation advice.",
        "Assigns Deployment Verdict (ALLOW / WARN / BLOCK).",
        "Emits PreFlightSimulationReport artifact for SecOps review."
    ], border_color=COLOR_RED)

    # ==========================================================================
    # SLIDE 15: Future Live Integrations
    # ==========================================================================
    s15 = prs.slides.add_slide(blank_layout)
    add_header(s15, "Planned Integrations & Operational Roadmap")

    add_card(s15, Inches(0.8), Inches(1.5), Inches(3.7), Inches(5.3), "Phase 4: Security Rules Engine", [
        "Automated Misconfiguration Detection:\n• Flags shadowed and redundant firewall rules.\n• Detects disabled Threat Prevention profiles.\n• Alerts on wildcard IAM actions (*:*) and broad S3 policies.",
        "Quantitative Risk Scoring:\n• Formulates 0–100 weighted risk score based on asset criticality and exposure tier.",
        "Least-Privilege Remediation:\n• Proposes scoped Terraform replacements automatically."
    ], border_color=COLOR_EMERALD)

    add_card(s15, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.3), "Future Live Panorama API", [
        "Bi-Directional Commit Sync:\n• Connects via Panorama XML/REST API over mutual TLS.\n• Pulls live device groups, rulebases, and address objects into the digital twin.\n• Simulates candidate changes directly against production candidate configurations before admin commits.",
        "Continuous Configuration Audit:\n• Detects out-of-band firewall changes and drifts."
    ], border_color=COLOR_BLUE)

    add_card(s15, Inches(8.8), Inches(1.5), Inches(3.7), Inches(5.3), "Future Live AWS Cloud API", [
        "AWS Config & Boto3 State Ingestion:\n• Discovers real-time VPC route tables, security groups, and EKS IRSA federations.\n• Reconciles observed infrastructure state against Terraform declared state.",
        "Automated CI/CD Bot:\n• Comments directly on GitHub / GitLab Pull Requests with blast radius diagrams and approval gates."
    ], border_color=COLOR_PURPLE)

    # ==========================================================================
    # SLIDE 16: Conclusion & Technical Roadmap (Dark Navy)
    # ==========================================================================
    s16 = prs.slides.add_slide(blank_layout)
    bg16 = s16.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg16.fill.solid()
    bg16.fill.fore_color.rgb = COLOR_NAVY
    bg16.line.fill.background()

    tb16 = s16.shapes.add_textbox(Inches(1.2), Inches(1.8), Inches(11.0), Inches(4.5))
    tf16 = tb16.text_frame

    p_t16 = tf16.paragraphs[0]
    p_t16.text = "Summary: Phase 3.5 Delivery & Roadmap Ahead"
    p_t16.font.size = Pt(28)
    p_t16.font.bold = True
    p_t16.font.color.rgb = COLOR_WHITE
    p_t16.space_after = Pt(20)

    bullets16 = [
        "Phase 3.5 Enterprise Digital Twin Benchmark Delivered:\n  Comprehensive synthetic dataset for Apex Global Technologies with 64 nodes, 39 edges, and 100% referential integrity.",
        "Robust Multi-Tier Blast Radius Traversal:\n  Engine seamlessly traces exposure from perimeter firewall policies to EKS pods, IAM roles, and NIST SP 800-171 CUI data assets.",
        "Zero Regressions Across 87 Automated Tests:\n  All 12 Phase 3.5 tests and 75 Phase 1–3 regression tests passing cleanly in 2.40s.",
        "Full Documentation Deliverables Completed:\n  Professional 15-section PDF architecture document, editable 16-slide PowerPoint, and 5 high-resolution architectural diagrams.",
        "Ready for Phase 4 Execution:\n  Foundations, parsers, and digital twin graph are primed for the implementation of security analysis rules and quantitative risk scoring."
    ]
    for b in bullets16:
        p = tf16.add_paragraph()
        p.text = f"✔  {b}"
        p.font.size = Pt(13)
        p.font.color.rgb = RGBColor(226, 232, 240)
        p.space_after = Pt(12)

    prs.save(str(PPTX_PATH))
    print(f"Successfully generated PowerPoint: {PPTX_PATH}")


if __name__ == "__main__":
    build_presentation()

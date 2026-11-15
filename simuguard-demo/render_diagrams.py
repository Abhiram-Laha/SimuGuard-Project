"""High-Resolution Diagram Renderer for SimuGuard AI Enterprise Documentation.
Generates 5 professional architectural diagrams based on the Apex Global Technologies dataset.
Output: PNG images saved to deliverables/diagrams/
"""

import sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Directory setup
OUT_DIR = Path(__file__).resolve().parent / "deliverables" / "diagrams"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Common styling constants
NAVY = "#0f172a"
SLATE = "#334155"
LIGHT_BG = "#f8fafc"
BORDER_GRAY = "#cbd5e1"
TEXT_DARK = "#1e293b"
TEXT_MUTED = "#64748b"

COLOR_FW = "#ef4444"       # Red for firewalls / perimeters
COLOR_MGMT = "#8b5cf6"     # Purple for Panorama / mgmt
COLOR_DMZ = "#f59e0b"      # Amber for DMZ
COLOR_PROD = "#10b981"     # Emerald for Production
COLOR_DEV = "#06b6d4"      # Cyan for Development
COLOR_SECOPS = "#ec4899"   # Pink for Security / Audit
COLOR_DATA = "#a855f7"     # Violet for Sensitive Data
COLOR_IAM = "#3b82f6"      # Blue for IAM / Identity
COLOR_FUTURE = "#f97316"   # Orange dashed for Planned roadmap


def draw_box(ax, x, y, w, h, title="", subtitle="", bg="#ffffff", border=BORDER_GRAY, lw=1.5, ls="-", rx=0.015, title_color=TEXT_DARK, sub_color=TEXT_MUTED, title_size=10, sub_size=8):
    """Draw a rounded rectangle with title and subtitle."""
    rect = patches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad={rx}",
        linewidth=lw,
        edgecolor=border,
        facecolor=bg,
        linestyle=ls,
        zorder=2
    )
    ax.add_patch(rect)
    if title:
        ax.text(x + w/2, y + h - 0.025, title, ha="center", va="top", fontsize=title_size, fontweight="bold", color=title_color, zorder=3)
    if subtitle:
        ax.text(x + w/2, y + h/2 - 0.01, subtitle, ha="center", va="center", fontsize=sub_size, color=sub_color, zorder=3)
    return rect


def draw_arrow(ax, x1, y1, x2, y2, label="", color="#475569", lw=1.5, ls="-", label_color=TEXT_DARK, rad=0.0):
    """Draw a styled directional arrow with optional centered text label."""
    ax.annotate(
        "",
        xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle="->,head_width=0.3,head_length=0.4",
            color=color,
            lw=lw,
            linestyle=ls,
            connectionstyle=f"arc3,rad={rad}",
        ),
        zorder=4
    )
    if label:
        mx, my = (x1 + x2)/2, (y1 + y2)/2
        ax.text(mx, my + 0.015, label, ha="center", va="bottom", fontsize=7.5, fontweight="bold", color=label_color, bbox=dict(boxstyle="round,pad=0.2", facecolor="#ffffff", edgecolor=BORDER_GRAY, lw=0.5, alpha=0.9), zorder=5)


# ==============================================================================
# 1. NETWORK ARCHITECTURE DIAGRAM
# ==============================================================================
def render_network_architecture():
    fig, ax = plt.subplots(figsize=(16, 10), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor(LIGHT_BG)

    # Title header
    ax.text(0.04, 0.96, "Apex Global Technologies – Enterprise Network Topology", fontsize=18, fontweight="bold", color=NAVY)
    ax.text(0.04, 0.935, "PAN-OS 11.1 Perimeter & Internal Core Firewalls, AWS Multi-VPC Architecture & 9 Security Zones", fontsize=10, color=TEXT_MUTED)

    # External Zone Container
    draw_box(ax, 0.04, 0.70, 0.22, 0.20, "EXTERNAL INGRESS & USERS", "", bg="#f1f5f9", border="#94a3b8")
    draw_box(ax, 0.05, 0.79, 0.20, 0.08, "Public Internet", "0.0.0.0/0", bg="#ffffff", border=BORDER_GRAY)
    draw_box(ax, 0.05, 0.71, 0.095, 0.07, "Corp Users", "10.10.0.0/16", bg="#ffffff", border=BORDER_GRAY)
    draw_box(ax, 0.155, 0.71, 0.095, 0.07, "Partner Webhook", "198.51.100.0/24", bg="#ffffff", border=BORDER_GRAY)

    # Panorama Management
    draw_box(ax, 0.30, 0.78, 0.28, 0.12, "PANORAMA 11.1 MANAGEMENT", "Host: pan-mgmt-01 (10.250.1.10) | OOB-Mgmt\nDevice Groups: Perimeter, Internal, Shared", bg="#ede9fe", border=COLOR_MGMT)

    # Perimeter Firewalls
    draw_box(ax, 0.04, 0.38, 0.26, 0.28, "PERIMETER FIREWALL (PA-5450 HA)", "Device Group: DG-Internet-Perimeter\nZones: Untrust, Trust-DMZ, Corp, Transit", bg="#fee2e2", border=COLOR_FW)
    draw_box(ax, 0.05, 0.51, 0.24, 0.09, "fw-edge-01-primary (Active)", "10.100.4.1 | VR: vr-default-edge\nRulebase: 22 L7 App-ID Rules", bg="#ffffff", border=COLOR_FW)
    draw_box(ax, 0.05, 0.40, 0.24, 0.09, "fw-edge-02-secondary (Standby)", "HA1 Control (10.255.1.1) / HA2 Sync\nStateful Session Synchronization", bg="#ffffff", border="#f87171", ls="--")

    # Transit Interconnect
    draw_box(ax, 0.34, 0.50, 0.20, 0.14, "TRANSIT INTERCONNECT", "Zone: Transit-Internal\nSubnet: 10.255.0.0/30 (VLAN 99)\nCross-Chassis Backbone", bg="#f8fafc", border="#64748b")

    # Internal Core Firewalls
    draw_box(ax, 0.58, 0.50, 0.38, 0.24, "INTERNAL SEGREGATION FIREWALL (PA-3440 HA)", "Device Group: DG-Internal-Segmentation | Enforces Zero-Trust Zone Isolation\nProtected Zones: Prod-App, Dev-App, Database, PCI-Cardholder, Vault", bg="#fee2e2", border=COLOR_FW)
    draw_box(ax, 0.60, 0.52, 0.16, 0.14, "fw-internal-01-primary", "Active (10.255.0.2)\nVR: vr-internal-core", bg="#ffffff", border=COLOR_FW)
    draw_box(ax, 0.78, 0.52, 0.16, 0.14, "fw-internal-02-secondary", "Passive (HA Sync)\nDedicated HA Links", bg="#ffffff", border="#f87171", ls="--")

    # AWS Production VPC Container
    draw_box(ax, 0.04, 0.04, 0.62, 0.30, "AWS PRODUCTION ACCOUNT: 111122223333 (VPC: vpc-prod-us-east-1 | 10.100.0.0/16)", "", bg="#ecfdf5", border=COLOR_PROD)
    
    # Zone: Trust-DMZ
    draw_box(ax, 0.05, 0.06, 0.14, 0.24, "Zone: Trust-DMZ", "10.100.4.0/24 (VLAN 10)\nALB: alb-customer-portal-ext\nPublic VIP: 203.0.113.20\nPods: eks-analytics-worker-pool", bg="#fffbeb", border=COLOR_DMZ)
    
    # Zone: Prod-App-Workloads
    draw_box(ax, 0.20, 0.06, 0.14, 0.24, "Zone: Prod-App", "10.100.10.0/23 (VLAN 20)\nEKS: eks-customer-portal-cluster\nAPI GW: alb-internal-api-gateway", bg="#ffffff", border=COLOR_PROD)

    # Zone: Database-Backend
    draw_box(ax, 0.35, 0.06, 0.14, 0.24, "Zone: Database", "10.100.20.0/24 (VLAN 30)\nRDS: rds-postgres-core-prod\nPostgreSQL Multi-AZ Cluster", bg="#ffffff", border=COLOR_PROD)

    # Zone: PCI-Cardholder
    draw_box(ax, 0.50, 0.06, 0.15, 0.24, "Zone: PCI-Cardholder", "10.100.30.0/24 (VLAN 40)\nStrict PCI CDE Enclave\nEKS: eks-payment-processor-pool\nDB: rds-pci-token-vault-prod", bg="#fce7f3", border=COLOR_SECOPS)

    # AWS Dev & Vault / SecOps (Right side)
    draw_box(ax, 0.68, 0.20, 0.28, 0.14, "Zone: Restricted-Data-Vault", "10.100.40.0/24 (VLAN 50)\nS3: s3-enterprise-cui-vault (NIST 800-171 CUI)\nKMS: kms-cui-vault | Strict Tokenization", bg="#fae8ff", border=COLOR_DATA)
    draw_box(ax, 0.68, 0.04, 0.28, 0.14, "AWS Development (222233334444)", "Zone: Dev-App-Workloads (10.200.10.0/23)\nEKS: eks-dev-sandbox-cluster\nS3: s3-dev-staging-telemetry", bg="#ecfeff", border=COLOR_DEV)

    # Arrows & Traffic Flow
    draw_arrow(ax, 0.15, 0.70, 0.15, 0.66, "HTTPS Ingress")
    draw_arrow(ax, 0.15, 0.38, 0.12, 0.30, "DNAT to DMZ")
    draw_arrow(ax, 0.30, 0.48, 0.34, 0.52, "Internal Transit")
    draw_arrow(ax, 0.54, 0.57, 0.58, 0.57, "L7 Inspection")
    draw_arrow(ax, 0.68, 0.50, 0.27, 0.30, "App Interconnect", rad=0.2)
    draw_arrow(ax, 0.70, 0.50, 0.42, 0.30, "DB Queries", rad=0.1)
    draw_arrow(ax, 0.75, 0.50, 0.57, 0.30, "Isolated CDE", rad=0.1)
    draw_arrow(ax, 0.78, 0.50, 0.78, 0.34, "CUI Strict Flow")
    draw_arrow(ax, 0.44, 0.78, 0.20, 0.66, "Policy Commit Push", color=COLOR_MGMT, ls=":")
    draw_arrow(ax, 0.44, 0.78, 0.68, 0.74, "Policy Commit Push", color=COLOR_MGMT, ls=":")

    plt.tight_layout()
    fig.savefig(OUT_DIR / "network_architecture.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Rendered:", OUT_DIR / "network_architecture.png")


# ==============================================================================
# 2. ENTERPRISE ORGANISATION ARCHITECTURE
# ==============================================================================
def render_enterprise_organisation():
    fig, ax = plt.subplots(figsize=(16, 10), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor(LIGHT_BG)

    # Title header
    ax.text(0.04, 0.96, "Apex Global Technologies – Enterprise Organisation Architecture", fontsize=18, fontweight="bold", color=NAVY)
    ax.text(0.04, 0.935, "AWS Multi-Account Governance, Palo Alto Management, Application Portfolios & Data Assets", fontsize=10, color=TEXT_MUTED)

    # Organization Parent Container
    draw_box(ax, 0.04, 0.78, 0.92, 0.13, "APEX GLOBAL TECHNOLOGIES INC. (apex-global.example)", "Executive Security Governance: NIST CSF 2.0 (PR.AC, PR.PT) | NIST SP 800-171 Rev 2 | PCI-DSS v4.0 | CIS Benchmarks", bg="#eff6ff", border="#3b82f6", lw=2)

    # Central Panorama & SIEM
    draw_box(ax, 0.04, 0.58, 0.28, 0.17, "CENTRAL SECURITY & MANAGEMENT", "Panorama 11.1 (pan-mgmt-01)\nDG-Enterprise-Shared (Global Policies)\nEnterprise SIEM / Splunk Cloud (10.250.1.50)\nVPC Flow & CloudTrail Aggregation", bg="#ede9fe", border=COLOR_MGMT)

    # AWS Organization Container
    draw_box(ax, 0.34, 0.05, 0.62, 0.70, "AWS ORGANIZATION: o-apexglobal01", "", bg="#f8fafc", border="#64748b", lw=2)

    # Production Account
    draw_box(ax, 0.36, 0.28, 0.58, 0.44, "PRODUCTION ACCOUNT: 111122223333 (OU: ou-apex-workloads)", "VPC: vpc-prod-us-east-1 (10.100.0.0/16)", bg="#ecfdf5", border=COLOR_PROD)
    
    # Production Applications
    draw_box(ax, 0.38, 0.48, 0.26, 0.18, "Tier-1 Customer Services", "APP-001: Customer Web Portal\nAPP-007: Core API Gateway (mTLS)\nAPP-008: Order Management Engine", bg="#ffffff", border=COLOR_PROD)
    draw_box(ax, 0.66, 0.48, 0.26, 0.18, "Tier-1 Payment & Analytics", "APP-002: PCI Payment Tokenizer\nAPP-003: Analytics Ingestion Pipeline\nAPP-009: Real-time Ingestion Stream", bg="#ffffff", border=COLOR_PROD)

    # Production Data Stores
    draw_box(ax, 0.38, 0.31, 0.26, 0.14, "Transactional Data Stores", "DATA-03: Customer PII DB (RDS Postgres)\nDATA-02: PCI Token Vault (RDS Postgres)", bg="#ffffff", border=COLOR_DATA)
    draw_box(ax, 0.66, 0.31, 0.26, 0.14, "Restricted Vault Storage", "DATA-01: CUI Financial Ledger (S3 Vault)\ns3-enterprise-cui-vault (KMS Encrypted)", bg="#fae8ff", border=COLOR_DATA)

    # Development Account
    draw_box(ax, 0.36, 0.07, 0.28, 0.19, "DEVELOPMENT: 222233334444", "OU: ou-apex-workloads | VPC: 10.200.0.0/16\nAPP-011: Developer Sandbox Platform\nDATA-06: s3-dev-staging-telemetry", bg="#ecfeff", border=COLOR_DEV)

    # Security Operations Account
    draw_box(ax, 0.66, 0.07, 0.28, 0.19, "SECURITY OPERATIONS: 333344445555", "OU: ou-apex-security | VPC: 10.250.0.0/16\nAPP-010: Central Security SIEM Ingestion\nDATA-05: s3-central-security-cloudtrail-sec", bg="#fce7f3", border=COLOR_SECOPS)

    # Departmental & Architecture Labels (Left bottom)
    draw_box(ax, 0.04, 0.05, 0.28, 0.50, "DEPARTMENTAL ARCHITECTURE", "• FinTech Operations:\n  Owns Customer Portal, Payments, Token Vault.\n• Data & Analytics Engineering:\n  Maintains Ingestion cluster and S3 pipelines.\n• SecOps & Compliance:\n  Enforces PAN-OS firewalls, OIDC, IRSA, and SIEM.\n• Infrastructure DevOps:\n  Manages Terraform CI/CD, VPCs, and EKS.\n\nSimuGuard AI Governance Role:\n  Validates all Terraform changes prior to commit\n  against the digital twin graph topology.", bg="#ffffff", border=BORDER_GRAY)

    # Connections
    draw_arrow(ax, 0.18, 0.78, 0.18, 0.75, "Security Mandate")
    draw_arrow(ax, 0.32, 0.66, 0.36, 0.60, "Config Commits", color=COLOR_MGMT)
    draw_arrow(ax, 0.51, 0.48, 0.51, 0.45, "DB Access", color=COLOR_PROD)
    draw_arrow(ax, 0.79, 0.48, 0.79, 0.45, "Scoped Writes", color=COLOR_PROD)
    draw_arrow(ax, 0.64, 0.57, 0.66, 0.57, "Service Calls (mTLS)")
    draw_arrow(ax, 0.64, 0.28, 0.72, 0.26, "Centralized Auditing", color=COLOR_SECOPS, ls="--")

    plt.tight_layout()
    fig.savefig(OUT_DIR / "enterprise_organisation.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Rendered:", OUT_DIR / "enterprise_organisation.png")


# ==============================================================================
# 3. IAM ARCHITECTURE DIAGRAM
# ==============================================================================
def render_iam_architecture():
    fig, ax = plt.subplots(figsize=(16, 10), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor(LIGHT_BG)

    # Title header
    ax.text(0.04, 0.96, "Apex Global Technologies – Cloud IAM Architecture", fontsize=18, fontweight="bold", color=NAVY)
    ax.text(0.04, 0.935, "Roles, Trust Policies, IRSA Federation, Permission Boundaries, and Target Cloud Resources", fontsize=10, color=TEXT_MUTED)

    # Column 1: Identities & Principals
    draw_box(ax, 0.04, 0.05, 0.26, 0.86, "1. IDENTITIES & OIDC FEDERATION", "", bg="#f8fafc", border="#64748b")
    draw_box(ax, 0.05, 0.70, 0.24, 0.18, "EKS IRSA OIDC Federation", "oidc.eks.us-east-1.amazonaws.com\n• sa: analytics-ingestion-sa\n• sa: customer-portal-sa\n• sa: payment-processor-sa\nFederated token exchange via IRSA", bg="#eff6ff", border=COLOR_IAM)
    draw_box(ax, 0.05, 0.48, 0.24, 0.18, "IAM User Principals", "• usr-dev-lead (222233334444)\n• usr-secops-analyst (333344445555)\n• grp-cloud-engineers\n• grp-security-audit\nMFA enforced on privileged groups", bg="#ffffff", border=COLOR_IAM)
    draw_box(ax, 0.05, 0.08, 0.24, 0.36, "Identity Boundaries vs Permissions", "Identity Relationship:\nDefines WHO can assume an IAM role\n(Trust Policy / OIDC federation).\n\nResource Permission:\nDefines WHAT actions the assumed role\ncan execute against AWS resources\n(Identity-based & Resource-based policies).\n\nSimuGuard AI monitors both layers\nto detect privilege escalation.", bg="#ffffff", border=BORDER_GRAY)

    # Column 2: IAM Roles
    draw_box(ax, 0.33, 0.05, 0.24, 0.86, "2. ASSUMED IAM ROLES", "", bg="#f8fafc", border="#64748b")
    draw_box(ax, 0.34, 0.72, 0.22, 0.16, "role-analytics-ingestion-svc", "Account: 111122223333 (Production)\nTrust: Federated IRSA\nBaseline: Write to dev-staging only\n⚠️ PR Target: AmazonS3FullAccess", bg="#eff6ff", border=COLOR_IAM)
    draw_box(ax, 0.34, 0.54, 0.22, 0.15, "role-customer-portal-backend", "Account: 111122223333 (Production)\nTrust: Federated IRSA\nAccess: Scoped RDS & Customer S3", bg="#ffffff", border=COLOR_IAM)
    draw_box(ax, 0.34, 0.37, 0.22, 0.15, "role-payment-processor-pci", "Account: 111122223333 (Production)\nTrust: Federated IRSA\nAccess: Scoped Token DB & KMS", bg="#fce7f3", border=COLOR_SECOPS)
    draw_box(ax, 0.34, 0.20, 0.22, 0.15, "role-dev-developer-sandbox", "Account: 222233334444 (Dev)\nTrust: Dev Account Root\nAccess: PowerUserAccess in Dev", bg="#ecfeff", border=COLOR_DEV)
    draw_box(ax, 0.34, 0.07, 0.22, 0.11, "role-ci-cd-deployment-pipeline", "Account: 111122223333 (Prod)\n⚠️ Excessive Dev Trust\nAccess: AdministratorAccess", bg="#fee2e2", border=COLOR_FW)

    # Column 3: Permission Boundaries & Policies
    draw_box(ax, 0.60, 0.05, 0.18, 0.86, "3. BOUNDARIES & POLICIES", "", bg="#f8fafc", border="#64748b")
    draw_box(ax, 0.61, 0.72, 0.16, 0.16, "policy/ApexWorkloadBoundary", "Type: Permission Boundary\nDENY s3:* on cui-vault\nBlocks unauthorized workloads from\never accessing CUI Financial Vault", bg="#fffbeb", border=COLOR_DMZ)
    draw_box(ax, 0.61, 0.54, 0.16, 0.15, "CustomerPortalDatabaseAccess", "Customer Managed Policy\nScoped RDS Connect\nScoped s3:GetObject on portal prefix", bg="#ffffff", border=COLOR_IAM)
    draw_box(ax, 0.61, 0.37, 0.16, 0.15, "ApexStrictPCIBoundary", "Type: Permission Boundary\nDENY s3:*, dynamodb:*\nEnforces strict CDE segregation", bg="#fffbeb", border=COLOR_SECOPS)
    draw_box(ax, 0.61, 0.20, 0.16, 0.15, "ApexDevSandboxBoundary", "Type: Permission Boundary\nDENY prod/sec account access\nPrevents escalation across accounts", bg="#fffbeb", border=COLOR_DEV)
    draw_box(ax, 0.61, 0.07, 0.16, 0.11, "AdministratorAccess", "⚠️ Wildcard Action: *\nResource: *\nFull production root access", bg="#fee2e2", border=COLOR_FW)

    # Column 4: Target Cloud Resources
    draw_box(ax, 0.81, 0.05, 0.15, 0.86, "4. TARGET CLOUD ASSETS", "", bg="#f8fafc", border="#64748b")
    draw_box(ax, 0.82, 0.72, 0.13, 0.16, "s3-enterprise-cui-vault", "Restricted CUI/PII\nKMS: kms-cui-vault\nNIST SP 800-171 3.1.3", bg="#fae8ff", border=COLOR_DATA)
    draw_box(ax, 0.82, 0.54, 0.13, 0.15, "rds-postgres-core-prod", "Customer PII Database\nKMS: kms-customer-db\nGDPR Article 32", bg="#ffffff", border=COLOR_DATA)
    draw_box(ax, 0.82, 0.37, 0.13, 0.15, "rds-pci-token-vault-prod", "PCI Cardholder Data\nKMS: kms-pci-token\nPCI DSS Req 3.4", bg="#fce7f3", border=COLOR_SECOPS)
    draw_box(ax, 0.82, 0.20, 0.13, 0.15, "s3-dev-staging-telemetry", "Unclassified Test Data\nStandard SSE-S3\nNo Sensitive Content", bg="#ecfeff", border=COLOR_DEV)
    draw_box(ax, 0.82, 0.07, 0.13, 0.11, "AWS Core Infrastructure", "VPCs, Subnets, EKS, Route Tables,\nSecurity Groups across Prod", bg="#ffffff", border=BORDER_GRAY)

    # Connecting arrows
    draw_arrow(ax, 0.29, 0.79, 0.34, 0.79, "IRSA Bind")
    draw_arrow(ax, 0.29, 0.61, 0.34, 0.61, "IRSA Bind")
    draw_arrow(ax, 0.29, 0.44, 0.34, 0.44, "IRSA Bind")
    draw_arrow(ax, 0.56, 0.79, 0.61, 0.79, "Attached")
    draw_arrow(ax, 0.56, 0.61, 0.61, 0.61, "Attached")
    draw_arrow(ax, 0.56, 0.44, 0.61, 0.44, "Attached")
    draw_arrow(ax, 0.56, 0.12, 0.61, 0.12, "Attached", color=COLOR_FW)
    draw_arrow(ax, 0.77, 0.79, 0.82, 0.79, "Exfil Path", color=COLOR_FW, lw=2)
    draw_arrow(ax, 0.77, 0.61, 0.82, 0.61, "Authorized")
    draw_arrow(ax, 0.77, 0.44, 0.82, 0.44, "Authorized")
    draw_arrow(ax, 0.45, 0.20, 0.45, 0.18, "Insecure Cross-Account Assume", color=COLOR_FW, ls="--")

    plt.tight_layout()
    fig.savefig(OUT_DIR / "iam_architecture.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Rendered:", OUT_DIR / "iam_architecture.png")


# ==============================================================================
# 4. END-TO-END DATA FLOW DIAGRAM
# ==============================================================================
def render_end_to_end_data_flow():
    fig, ax = plt.subplots(figsize=(16, 10), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor(LIGHT_BG)

    # Title header
    ax.text(0.04, 0.96, "SimuGuard AI – End-to-End Network-to-IAM Data Flow & Blast Path", fontsize=18, fontweight="bold", color=NAVY)
    ax.text(0.04, 0.935, "Tracing Ingress Request from Internet through Firewalls, DMZ, Workloads, IAM IRSA to CUI Data Asset", fontsize=10, color=TEXT_MUTED)

    # 6 Major Stages
    steps = [
        ("1. INGRESS & PERIMETER", "Public Client / Attacker\nIP: 0.0.0.0/0\nTarget VIP: 203.0.113.20:443\nfw-edge-01-primary (PA-5450)\nEvaluates Rule: RULE-PAN-004", COLOR_FW, 0.04),
        ("2. DMZ SEGMENTATION", "Zone: Trust-DMZ\nSubnet: 10.100.4.0/24\nDestination NAT applied\nForwarded to ALB VIP\nalb-customer-portal-ext", COLOR_DMZ, 0.20),
        ("3. COMPUTE WORKLOAD", "eks-analytics-worker-pool\nCompute Pod (10.100.4.50)\nApplication Hosted:\nAPP-003: Customer Analytics\nClickstream Processing", COLOR_PROD, 0.36),
        ("4. OIDC IRSA FEDERATION", "role-analytics-ingestion-svc\nBound via ServiceAccount:\nanalytics-ingestion-sa\nAcquires temporary AWS STS\ncredentials in DMZ pod", COLOR_IAM, 0.52),
        ("5. S3 CROSS-ZONE ACCESS", "s3-enterprise-cui-vault\nPhysical Target Bucket\nPolicy PR Change:\nAmazonS3FullAccess attached!\nBypasses scoped boundary", COLOR_FUTURE, 0.68),
        ("6. SENSITIVE DATA ASSET", "DATA-01-CUI-FINANCIAL-VAULT\nClassification: RESTRICTED_CUI_PII\nNIST SP 800-171 3.1.3 Ledger\nEncrypted: kms-cui-vault\n⚠️ DATA COMPROMISED", COLOR_DATA, 0.84)
    ]

    for title, desc, col, x in steps:
        draw_box(ax, x, 0.45, 0.13, 0.42, title, desc, bg="#ffffff", border=col, lw=2, title_color=col, title_size=9, sub_size=7.5)

    # Horizontal Flow Arrows
    draw_arrow(ax, 0.17, 0.66, 0.20, 0.66, "1. Ingress & NAT", color=COLOR_FW, lw=2)
    draw_arrow(ax, 0.33, 0.66, 0.36, 0.66, "2. Route to Pod", color=COLOR_DMZ, lw=2)
    draw_arrow(ax, 0.49, 0.66, 0.52, 0.66, "3. IRSA Assume", color=COLOR_IAM, lw=2)
    draw_arrow(ax, 0.65, 0.66, 0.68, 0.66, "4. S3 Call (*)", color=COLOR_FUTURE, lw=2)
    draw_arrow(ax, 0.81, 0.66, 0.84, 0.66, "5. Read/Write", color=COLOR_DATA, lw=2)

    # Lower Diagnostic Panel
    draw_box(ax, 0.04, 0.06, 0.92, 0.34, "SIMUGUARD AI PRE-FLIGHT VERDICT & BLAST-RADIUS EVALUATION", "", bg="#ffffff", border="#475569", lw=2)
    
    panel_text = (
        "Evaluation Logic & Safety Governance:\n"
        "• Network Layer Check: Firewall policy allows ingress from Untrust-Internet to Trust-DMZ for HTTPS (Port 443).\n"
        "• Identity Layer Check: Pod in Trust-DMZ binds to role-analytics-ingestion-svc via EKS IRSA.\n"
        "• Security Gap Flagged: Terraform change PR #4083 attaches AmazonS3FullAccess to role-analytics-ingestion-svc.\n"
        "• Blast Propagation Traversal: Engine traverses role-analytics-ingestion-svc -> CROSS_ZONE_IAM_PATH -> s3-enterprise-cui-vault\n"
        "  -> STORES_DATA -> DATA-01-CUI-FINANCIAL-VAULT (Classification: RESTRICTED_CUI_PII).\n"
        "• Critical Finding: Unrestricted egress in DMZ combined with wildcard S3 permissions satisfies cross-zone exfiltration condition.\n"
        "• Verdict: BLOCK_DEPLOYMENT | Risk Score: 96/100 | Recommendation: Enforce scoped policy S3TelemetryWriteOnly."
    )
    ax.text(0.06, 0.34, panel_text, fontsize=9.5, color=TEXT_DARK, va="top", family="monospace")

    plt.tight_layout()
    fig.savefig(OUT_DIR / "end_to_end_data_flow.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Rendered:", OUT_DIR / "end_to_end_data_flow.png")


# ==============================================================================
# 5. SIMUGUARD AI PLATFORM ARCHITECTURE
# ==============================================================================
def render_simuguard_platform_architecture():
    fig, ax = plt.subplots(figsize=(16, 10), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor(LIGHT_BG)

    # Title header
    ax.text(0.04, 0.96, "SimuGuard AI – Platform Architecture & Pipeline", fontsize=18, fontweight="bold", color=NAVY)
    ax.text(0.04, 0.935, "Clear Distinction Between Implemented Core Components and Planned Future API Integrations", fontsize=10, color=TEXT_MUTED)

    # 1. Submission
    draw_box(ax, 0.04, 0.55, 0.16, 0.34, "1. CHANGE SUBMISSION", "DevOps / SecOps\n\nSubmits Terraform PR:\n• changes/allow_netflix.tf\n• changes/pr_4082.tf\n• changes/pr_4083.tf\n\nTrigger: Pre-Commit / CI/CD", bg="#eff6ff", border=COLOR_IAM)

    # 2. Ingestion & Normalization
    draw_box(ax, 0.23, 0.55, 0.16, 0.34, "2. INGESTION & NORM", "simuguard/parsers/\n\n• TerraformHclParser\n  (python-hcl2)\n• Resource Normalization:\n  - PanosSecurityPolicy\n  - AwsSecurityGroupRule\n  - AwsIamRolePolicyAttach\n[IMPLEMENTED]", bg="#ecfdf5", border=COLOR_PROD)

    # 3. Digital Twin Engine
    draw_box(ax, 0.42, 0.55, 0.18, 0.34, "3. DIGITAL TWIN GRAPH", "simuguard/graph/\n\n• EnterpriseDatasetLoader\n• NetworkX DiGraph Engine\n  64 Nodes | 39 Edges\n• Referential Integrity\n• SG & Workload Mappings\n[IMPLEMENTED]", bg="#ecfdf5", border=COLOR_PROD)

    # 4. Security & Blast Radius
    draw_box(ax, 0.63, 0.55, 0.16, 0.34, "4. BLAST ENGINE", "simuguard/graph/blast_radius\n\n• Direct & Cascading Traversal\n• Downstream Data Assets\n• Hosted Applications\n• Unknown Unmapped Handler\n[IMPLEMENTED]", bg="#ecfdf5", border=COLOR_PROD)

    # 5. Output & Governance
    draw_box(ax, 0.82, 0.55, 0.14, 0.34, "5. VERDICT & REPORT", "PreFlightSimulationReport\n\n• DeploymentVerdict:\n  ALLOW | WARN | BLOCK\n• Security Gaps List\n• JSON & MD Artifacts\n[IMPLEMENTED]", bg="#fce7f3", border=COLOR_SECOPS)

    # Arrows between main pipeline
    draw_arrow(ax, 0.20, 0.72, 0.23, 0.72, "PR Files")
    draw_arrow(ax, 0.39, 0.72, 0.42, 0.72, "Normalized")
    draw_arrow(ax, 0.60, 0.72, 0.63, 0.72, "Graph Query")
    draw_arrow(ax, 0.79, 0.72, 0.82, 0.72, "Simulation")

    # Bottom Row: Implemented vs Planned Future Integrations
    draw_box(ax, 0.04, 0.08, 0.44, 0.38, "CURRENTLY IMPLEMENTED COMPONENTS (PHASES 1 - 3.5)", "• Pydantic v2 Type-Safe Schemas & Enums (Severity, Verdict, Criticality)\n• Robust python-hcl2 Parser with Syntax vs Schema validation\n• 64-Node Enterprise Digital Twin (Apex Global Technologies)\n• Multi-Tier Blast Radius Traversal (Network -> Workload -> IAM -> Data)\n• Strict Unmapped Resource Governance (UNKNOWN status, never safe)\n• 87 Fully Passing Automated Regression Tests (0 Failures)", bg="#ffffff", border=COLOR_PROD, lw=2, title_color=COLOR_PROD)

    draw_box(ax, 0.52, 0.08, 0.44, 0.38, "PLANNED ROADMAP INTEGRATIONS (PHASE 4 & FUTURE)", "• Phase 4 Security Rules Engine: Inactive/Shadowed/Wildcard Policy Rules\n• Phase 4 Quantitative Scoring: 0-100 Weighted Risk Scoring Algorithm\n• Phase 4 Remediation: Least-Privilege Terraform Fix Generation\n• Future Live Panorama API: Automated bi-directional XML/REST commit sync\n• Future Live AWS Cloud API: Real-time AWS Config and boto3 state discovery\n• Future CI/CD PR Bot: Automated GitHub/GitLab PR Commenter & Gate", bg="#fff7ed", border=COLOR_FUTURE, lw=2, ls="--", title_color=COLOR_FUTURE)

    plt.tight_layout()
    fig.savefig(OUT_DIR / "simuguard_platform_architecture.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Rendered:", OUT_DIR / "simuguard_platform_architecture.png")


if __name__ == "__main__":
    print("Starting diagram rendering...")
    render_network_architecture()
    render_enterprise_organisation()
    render_iam_architecture()
    render_end_to_end_data_flow()
    render_simuguard_platform_architecture()
    print("All 5 diagrams successfully rendered!")

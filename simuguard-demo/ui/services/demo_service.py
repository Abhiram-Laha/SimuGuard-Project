"""Demo Environment Management Service for SimuGuard AI (Milestone G).

Provides repeatable, idempotent initialization and reset of the isolated demo database:
1. Scenario 1: Dangerous Firewall Change (PR-4083, App-ID bypass, BLOCK)
2. Scenario 2: Excessive AWS IAM Permissions (PR-4082, S3FullAccess CUI Vault, BLOCK)
3. Scenario 3: SailPoint Privileged Access (Sophia Alvarez contractor prod admin, BLOCK)
4. Scenario 4: Safe Firewall Change (demo_safe_firewall.tf, scoped partner, ALLOW)
5. Scenario 5: Unknown/Unmapped Entity (allow_netflix.tf, unmapped SG, WARN_MANUAL_REVIEW)

Guarantees:
- Never populates or mutates the production database (simuguard_history.db).
- All demo records are strictly labeled with SIM-DEMO- identifiers.
- Repeatable and idempotent reset mechanism.
"""

from pathlib import Path
import sqlite3
from typing import Dict, List, Optional
import json

from config.settings import CHANGES_DIR, DEMO_DB_PATH
from storage.database import init_db
from storage.models import (
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.services.assessment_runner import AssessmentRunnerService


DEMO_SCENARIO_CONFIGS = [
    {
        "request_number": "SIM-DEMO-001",
        "title": "[DEMO-01] Dangerous Firewall Policy Widening (App-ID Bypass & IAM)",
        "description": "Widened perimeter egress rule for analytics webhook cluster with application='any' and broad S3 FullAccess policy attachment.",
        "justification": "Customer Telemetry & Analytics pipeline integration required for real-time telemetry streaming.",
        "change_type": ChangeType.FIREWALL_POLICY.value,
        "domain": ChangeDomain.NETWORK_SECURITY.value,
        "priority": ChangePriority.CRITICAL.value,
        "scenario_filename": "pr_4083_firewall_iam.tf",
        "configuration_item": "PAN-NGFW-EDGE-01",
        "assignment_group": "SecOps-Perimeter-Team",
        "submitted_by": "Alex Rivera (SecOps)",
    },
    {
        "request_number": "SIM-DEMO-002",
        "title": "[DEMO-02] Excessive Cloud IAM Privilege Escalation (CUI Vault Path)",
        "description": "Attached broad managed policy AmazonS3FullAccess to ingestion cluster service role, satisfying cross-zone path to Restricted CUI Financial Vault.",
        "justification": "Analytics worker pool requires write access for staging data upload.",
        "change_type": ChangeType.FIREWALL_POLICY.value,
        "domain": ChangeDomain.NETWORK_SECURITY.value,
        "priority": ChangePriority.HIGH.value,
        "scenario_filename": "pr_4082_firewall_iam.tf",
        "configuration_item": "AWS-IAM-ROLE-ANALYTICS",
        "assignment_group": "CloudOps-IAM-Team",
        "submitted_by": "Morgan Chen (Cloud Eng)",
    },
    {
        "request_number": "SIM-DEMO-003",
        "title": "[DEMO-03] Contractor Privileged Access Request (SoD & Policy Violation)",
        "description": "Access grant requesting Production Administrator privileged profile for external contractor Sophia Alvarez (violates policy SP-04 and SoD matrix).",
        "justification": "Contractor requested elevated production administrator access for database migration testing.",
        "change_type": ChangeType.SAILPOINT_GOVERNANCE.value,
        "domain": ChangeDomain.IDENTITY_GOVERNANCE.value,
        "priority": ChangePriority.CRITICAL.value,
        "scenario_filename": None,
        "configuration_item": "SailPoint Identity Security Cloud",
        "assignment_group": "IAM-Governance-Team",
        "submitted_by": "Jordan Taylor (Identity Admin)",
        "sailpoint_details": {
            "identity_id": "sp-ident-sophia-alvarez",
            "identity_name": "Sophia Alvarez",
            "identity_profile": "sp-idp-external-contractors",
            "identity_source": "Contractor HR Ingestion Source",
            "account_id": "sp-acc-sophia-alvarez-aws-dev",
            "account_status": "ACTIVE",
            "requested_role": "sp-role-production-administrator",
            "access_profile": "sp-prof-prod-admin",
            "entitlement": "arn:aws:iam::aws:policy/AdministratorAccess",
            "application_name": "AWS Production Multi-Account",
            "business_justification": "Emergency contractor production migration access.",
            "request_status": "SUBMITTED",
            "approval_status": "PENDING",
            "provisioning_status": "UNPROVISIONED",
        },
    },
    {
        "request_number": "SIM-DEMO-004",
        "title": "[DEMO-04] Safe Scoped Perimeter Firewall Policy (Strict App-ID & Partner CIDR)",
        "description": "Scoped SIEM log forwarder egress rule to verified corporate partner CIDR (52.84.120.0/22) with SSL App-ID and threat prevention profile.",
        "justification": "Scheduled quarterly SIEM collector connection update according to enterprise standard.",
        "change_type": ChangeType.FIREWALL_POLICY.value,
        "domain": ChangeDomain.NETWORK_SECURITY.value,
        "priority": ChangePriority.NORMAL.value,
        "scenario_filename": "demo_safe_firewall.tf",
        "configuration_item": "PAN-NGFW-EDGE-01",
        "assignment_group": "SecOps-Network-Team",
        "submitted_by": "Dana White (Network Sec)",
    },
    {
        "request_number": "SIM-DEMO-005",
        "title": "[DEMO-05] Unmapped Entity Exception (Outside Digital Twin Topology)",
        "description": "Egress security group rule referencing unmapped security group sg-guest-network-01 with non-standard destination format.",
        "justification": "Temporary guest network streaming access for employee lounge.",
        "change_type": ChangeType.FIREWALL_POLICY.value,
        "domain": ChangeDomain.NETWORK_SECURITY.value,
        "priority": ChangePriority.LOW.value,
        "scenario_filename": "allow_netflix.tf",
        "configuration_item": "AWS-SG-GUEST-01",
        "assignment_group": "Office-IT-Support",
        "submitted_by": "Sam Wilson (DevOps)",
    },
]


class DemoEnvironmentService:
    """Manages the isolated demonstration database and pre-computed demo scenarios."""

    @staticmethod
    def get_demo_db_path() -> Path:
        """Return the absolute path of the demo database."""
        return DEMO_DB_PATH

    @classmethod
    def get_demo_repository(cls) -> ChangeRepository:
        """Obtain a ChangeRepository instance pointing strictly to the demo database."""
        cls.ensure_demo_initialized()
        return ChangeRepository(db_path=str(DEMO_DB_PATH))

    @classmethod
    def is_demo_initialized(cls) -> bool:
        """Check whether the demo database exists and contains all 5 demo scenarios."""
        if not DEMO_DB_PATH.exists():
            return False
        try:
            conn = sqlite3.connect(str(DEMO_DB_PATH))
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM change_requests WHERE request_number LIKE 'SIM-DEMO-%'")
            count = c.fetchone()[0]
            conn.close()
            return count >= 5
        except Exception:
            return False

    @classmethod
    def ensure_demo_initialized(cls) -> None:
        """Idempotently ensure demo database is ready."""
        if not cls.is_demo_initialized():
            cls.initialize_demo_database(force=True)

    @classmethod
    def reset_demo_database(cls) -> None:
        """Force a clean reset of the demo database."""
        cls.initialize_demo_database(force=True)

    @classmethod
    def initialize_demo_database(cls, force: bool = False) -> None:
        """Populate the demo database with the 5 enterprise demonstration scenarios."""
        if DEMO_DB_PATH.exists() and force:
            try:
                DEMO_DB_PATH.unlink(missing_ok=True)
            except Exception:
                pass

        init_db(DEMO_DB_PATH)
        repo = ChangeRepository(db_path=str(DEMO_DB_PATH))
        runner = AssessmentRunnerService(repository=repo)

        for cfg in DEMO_SCENARIO_CONFIGS:
            req_no = cfg["request_number"]
            existing = repo.get_change_request(req_no)
            if existing and not force:
                continue

            scenario_fn = cfg.get("scenario_filename")
            source_path = None
            raw_content = None

            if scenario_fn:
                p = CHANGES_DIR / scenario_fn
                if not p.exists():
                    p = CHANGES_DIR / "demo" / scenario_fn
                if p.exists():
                    source_path = str(p.resolve())
                    raw_content = p.read_text(encoding="utf-8")

            sailpoint_details_json = None
            if cfg.get("sailpoint_details"):
                sailpoint_details_json = json.dumps(cfg["sailpoint_details"])

            rec = ChangeRequestRecord(
                request_number=req_no,
                title=cfg["title"],
                description=cfg["description"],
                justification=cfg["justification"],
                submitted_by=cfg["submitted_by"],
                change_type=cfg["change_type"],
                domain=cfg["domain"],
                priority=cfg["priority"],
                status=WorkflowState.SUBMITTED.value,
                configuration_item=cfg["configuration_item"],
                assignment_group=cfg["assignment_group"],
                scenario_name=scenario_fn,
                source_file_path=source_path,
                raw_content=raw_content,
                sailpoint_details_json=sailpoint_details_json,
                implementation_plan="Execute automated pipeline deployment following SimuGuard pre-flight CAB review.",
                technical_approach="Deterministic graph simulation with candidate overlay comparison.",
                backout_plan="Roll back to previous certified Git state.",
                validation_plan="Pre-implementation validation playbook checks.",
                maintenance_window="Weekend Production Window",
            )
            repo.create_change_request(rec)

            # Assess change request
            runner.run_assessment(req_no, force_reassessment=True)

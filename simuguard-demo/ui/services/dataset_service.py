"""Dataset access service to populate UI selectors from the Apex Global Digital Twin."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from config.settings import CHANGES_DIR, DEMO_ENV_DIR


class DatasetService:
    """Service providing read-only access to synthetic Digital Twin resources."""

    def __init__(self, demo_dir: Optional[Path] = None, changes_dir: Optional[Path] = None):
        self.demo_dir = demo_dir or DEMO_ENV_DIR
        self.changes_dir = changes_dir or CHANGES_DIR

    def _read_json_safe(self, rel_path: str) -> Dict[str, Any]:
        target = self.demo_dir / rel_path
        if not target.exists():
            return {}
        try:
            with open(target, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def get_available_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Return available demo Terraform scenarios confirmed on disk."""
        scenarios: Dict[str, Dict[str, Any]] = {}

        # 1. PR-4083: Palo Alto NGFW + IAM
        p4083 = self.changes_dir / "pr_4083_firewall_iam.tf"
        if p4083.exists():
            scenarios["pr_4083_firewall_iam.tf"] = {
                "filename": "pr_4083_firewall_iam.tf",
                "label": "PR #4083 — Palo Alto NGFW Webhook Egress & S3 CUI Exposure",
                "path": str(p4083),
                "domain": "NETWORK_SECURITY",
                "change_type": "FIREWALL_POLICY",
                "priority": "HIGH",
                "ci": "pan-vm-core-firewall-01 (Mgt/Prod Perimeter)",
                "application": "Data Lake Ingestion / Analytics Pipeline",
                "platform": "Palo Alto Networks PAN-OS 11.1",
                "description": "Opens outbound HTTPS to 0.0.0.0/0 on DMZ perimeter firewall and attaches AmazonS3FullAccess to analytics ingestion worker.",
                "justification": "Required for third-party analytics telemetry streaming and emergency staging data dump.",
            }

        # 2. PR-4082: AWS SG + IAM
        p4082 = self.changes_dir / "pr_4082_firewall_iam.tf"
        if p4082.exists():
            scenarios["pr_4082_firewall_iam.tf"] = {
                "filename": "pr_4082_firewall_iam.tf",
                "label": "PR #4082 — Analytics Egress Webhook & S3 FullAccess (AWS SG + IAM)",
                "path": str(p4082),
                "domain": "NETWORK_SECURITY",
                "change_type": "HYBRID_CHANGE",
                "priority": "NORMAL",
                "ci": "sg-analytics-web-01 / role-analytics-ingestion-svc",
                "application": "Analytics Processing Service",
                "platform": "AWS VPC Security Group / IAM",
                "description": "Allows analytics pods to push outbound logs to external webhooks and writes to S3 bucket.",
                "justification": "Fixes S3 AccessDenied errors in staging analytics cluster.",
            }

        # 3. PR-4101: allow_netflix
        p_netflix = self.changes_dir / "allow_netflix.tf"
        if p_netflix.exists():
            scenarios["allow_netflix.tf"] = {
                "filename": "allow_netflix.tf",
                "label": "PR #4101 — Allow Guest Network Netflix Streaming (AWS SG Egress)",
                "path": str(p_netflix),
                "domain": "NETWORK_SECURITY",
                "change_type": "FIREWALL_POLICY",
                "priority": "LOW",
                "ci": "sg-guest-network-01",
                "application": "Guest Corporate Wi-Fi Services",
                "platform": "AWS VPC Security Group",
                "description": "Allows corporate guest Wi-Fi subnet outbound HTTPS egress to Netflix streaming servers.",
                "justification": "Office guest breakroom amenity enhancement requested by Facilities.",
            }

        return scenarios

    def get_firewalls(self) -> List[Dict[str, Any]]:
        """Return list of Palo Alto firewalls."""
        data = self._read_json_safe("network/firewalls.json")
        return data.get("firewalls", [])

    def get_panoramas(self) -> Dict[str, Any]:
        """Return Panorama central management configuration."""
        data = self._read_json_safe("network/panorama.json")
        return data.get("panorama", {})

    def get_zones(self) -> List[Dict[str, Any]]:
        """Return enterprise network security zones."""
        data = self._read_json_safe("network/zones.json")
        return data.get("zones", [])

    def get_applications(self) -> List[Dict[str, Any]]:
        """Return enterprise business applications."""
        data = self._read_json_safe("applications/applications.json")
        return data.get("applications", [])

    def get_identities(self) -> List[Dict[str, Any]]:
        """Return SailPoint identity directory."""
        data = self._read_json_safe("sailpoint/identities.json")
        return data.get("identities", [])

    def get_identity_profiles(self) -> List[Dict[str, Any]]:
        """Return SailPoint identity profiles."""
        data = self._read_json_safe("sailpoint/identity_profiles.json")
        return data.get("identity_profiles", [])

    def get_sources(self) -> List[Dict[str, Any]]:
        """Return connected SailPoint authoritative and target sources."""
        data = self._read_json_safe("sailpoint/sources.json")
        return data.get("sources", [])

    def get_accounts(self) -> List[Dict[str, Any]]:
        """Return accounts connected across identity sources."""
        data = self._read_json_safe("sailpoint/accounts.json")
        return data.get("accounts", [])

    def get_roles(self) -> List[Dict[str, Any]]:
        """Return SailPoint business and IT roles."""
        data = self._read_json_safe("sailpoint/roles.json")
        return data.get("roles", [])

    def get_access_profiles(self) -> List[Dict[str, Any]]:
        """Return SailPoint access profiles."""
        data = self._read_json_safe("sailpoint/access_profiles.json")
        return data.get("access_profiles", [])

    def get_entitlements(self) -> List[Dict[str, Any]]:
        """Return SailPoint entitlements."""
        data = self._read_json_safe("sailpoint/entitlements.json")
        return data.get("entitlements", [])


_DATASET_SERVICE_INSTANCE: Optional[DatasetService] = None


def get_dataset_service() -> DatasetService:
    """Return singleton dataset service instance."""
    global _DATASET_SERVICE_INSTANCE
    if _DATASET_SERVICE_INSTANCE is None:
        _DATASET_SERVICE_INSTANCE = DatasetService()
    return _DATASET_SERVICE_INSTANCE

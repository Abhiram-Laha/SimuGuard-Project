"""Affected asset model representing an infrastructure node in the blast radius."""

import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from simuguard.models.enums import AssetCriticality, BlastTier


class AffectedAsset(BaseModel):
    """Represents an infrastructure asset impacted by the proposed change."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    asset_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier of the affected asset (matching topology node id or resource name)",
    )
    asset_name: Optional[str] = Field(
        default=None,
        description="Human-readable display name of the asset",
    )
    asset_type: Optional[str] = Field(
        default=None,
        description="Asset type (e.g., NGFW_Palo_Alto, Network_Zone, Compute_Cluster, IAM_Role, Storage_S3_Bucket)",
    )
    criticality: AssetCriticality = Field(
        default=AssetCriticality.HIGH,
        description="Criticality of the asset to enterprise operations",
    )
    blast_tier: BlastTier = Field(
        default=BlastTier.DIRECT,
        description="DIRECT (resource itself changed) or CASCADING (downstream zone or dependent asset exposed)",
    )
    impact_description: str = Field(
        ...,
        min_length=3,
        description="Specific explanation of how this asset is affected",
    )

    @field_validator("asset_id", "impact_description")
    @classmethod
    def strip_and_validate_non_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty or whitespace only")
        return cleaned

    def to_display_string(self) -> str:
        """Format as a human-readable display string."""
        tier_title = self.blast_tier.value.title()
        return f"{self.asset_id} ({tier_title}: {self.impact_description})"

    @classmethod
    def from_summary_string(
        cls,
        summary: str,
        default_criticality: AssetCriticality = AssetCriticality.HIGH,
    ) -> "AffectedAsset":
        """Parse a legacy or formatted summary string into a structured AffectedAsset.

        Example formats handled:
        - "pan-vm-core-firewall-01 (Direct: Security Rule 'Allow-Analytics-Outbound-Webhook' widened)"
        - "s3-enterprise-cui-vault (Cascading: Exposed to cross-bucket read/exfiltration)"
        - "subnet-trust-dmz: Egress opened to destination 'any'"
        """
        raw = summary.strip()
        pattern = r"^(?P<asset>[^()]+?)\s*\((?P<tier>Direct|Cascading):\s*(?P<desc>[^)]+)\)$"
        match = re.match(pattern, raw, re.IGNORECASE)

        if match:
            asset_id = match.group("asset").strip()
            tier_str = match.group("tier").strip().upper()
            tier = BlastTier.DIRECT if tier_str == "DIRECT" else BlastTier.CASCADING
            desc = match.group("desc").strip()
            return cls(
                asset_id=asset_id,
                blast_tier=tier,
                impact_description=desc,
                criticality=default_criticality,
            )

        # Fallback for plain "asset_id: description" or bare string
        if ":" in raw:
            parts = raw.split(":", 1)
            return cls(
                asset_id=parts[0].strip(),
                blast_tier=BlastTier.DIRECT,
                impact_description=parts[1].strip(),
                criticality=default_criticality,
            )

        return cls(
            asset_id=raw,
            blast_tier=BlastTier.DIRECT,
            impact_description=f"Asset impacted by proposed configuration update: {raw}",
            criticality=default_criticality,
        )

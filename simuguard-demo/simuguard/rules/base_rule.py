"""Base rule interface and supporting data structures for SimuGuard AI."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field
from simuguard.graph.digital_twin import DigitalTwinGraph
from simuguard.models.enums import Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import NormalizedResource


class RuleEvaluationContext(BaseModel):
    """Contextual information provided to rules during evaluation."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    digital_twin: Optional[DigitalTwinGraph] = Field(
        default=None,
        description="Active Digital Twin graph instance",
    )
    sailpoint_governance: Dict[str, Any] = Field(
        default_factory=dict,
        description="Loaded SailPoint governance dataset (identities, requests, prov, certs)",
    )
    all_resources: List[NormalizedResource] = Field(
        default_factory=list,
        description="All normalized resources in the change set",
    )
    extra_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary additional execution metadata",
    )


class BaseRule(ABC):
    """Abstract base class for all deterministic security rules."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    compliance_frameworks: List[str] = []

    @abstractmethod
    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        """Evaluate normalized resources against this security rule.

        Args:
            resources: List of normalized Terraform resources in scope.
            context: Shared evaluation context including graph and datasets.

        Returns:
            List of detected SecurityGap findings (empty if compliant).
        """
        pass

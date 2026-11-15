"""SimuGuard AI: Pre-deployment cybersecurity analysis and simulation platform.

Analyzes Infrastructure as Code (Terraform) changes, maps potential blast
radius across digital twin network topologies, flags security misconfigurations,
and prescribes least-privilege remediations.
"""

__version__ = "0.2.0"

from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.engine.risk_engine import RiskEngine, RiskScoreBreakdown
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import (
    AssetCriticality,
    BlastTier,
    DeploymentVerdict,
    ImpactStatus,
    Severity,
)
from simuguard.models.report import PreFlightSimulationReport
from simuguard.models.security_gap import SecurityGap
from simuguard.models.validation_check import ValidationCheck
from simuguard.reporters.json_reporter import JsonReporter
from simuguard.reporters.terminal_reporter import TerminalReporter

__all__ = [
    "__version__",
    "AssetCriticality",
    "BlastTier",
    "DeploymentVerdict",
    "ImpactStatus",
    "Severity",
    "AffectedAsset",
    "PreFlightSimulationReport",
    "SecurityGap",
    "ValidationCheck",
    "SimuGuardAnalyzer",
    "RiskEngine",
    "RiskScoreBreakdown",
    "TerminalReporter",
    "JsonReporter",
]

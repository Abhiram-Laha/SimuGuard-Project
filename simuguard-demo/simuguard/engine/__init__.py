"""Engine package for SimuGuard AI.

Contains core simulation orchestration:
- SimuGuardAnalyzer: Central pre-flight simulation coordinator
- RiskEngine: Deterministic risk scoring and verdict state machine
"""

from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.engine.risk_engine import (
    RiskEngine,
    RiskScoreBreakdown,
    SEVERITY_WEIGHTS,
    CRITICALITY_MULTIPLIERS,
)

__all__ = [
    "SimuGuardAnalyzer",
    "RiskEngine",
    "RiskScoreBreakdown",
    "SEVERITY_WEIGHTS",
    "CRITICALITY_MULTIPLIERS",
]

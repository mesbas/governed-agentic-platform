"""Governed Agentic Platform (GAP).

A reference runtime for enterprise systems in which AI agents and automations
take real actions. Every action passes through a policy engine, an optional
human approval step, a kill switch and budget limits, and is written to a
tamper-evident audit log.
"""

from .actions import ActionRequest, ActionResult, RiskTier
from .approvals import ApprovalQueue
from .audit import AuditLog
from .policy import PolicyDecision, PolicyEngine, PolicyRule, Verdict
from .runtime import GovernedRuntime, Tool

__all__ = [
    "ActionRequest",
    "ActionResult",
    "ApprovalQueue",
    "AuditLog",
    "GovernedRuntime",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRule",
    "RiskTier",
    "Tool",
    "Verdict",
]

__version__ = "0.1.0"

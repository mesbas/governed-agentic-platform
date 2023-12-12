"""Policy engine: decides whether an action is allowed, denied or needs approval.

Rules are evaluated together and the most restrictive matching verdict wins
(deny > require_approval > allow). If no rule matches, the default verdict
applies, which is deny unless configured otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .actions import ActionRequest, RiskTier


class Verdict(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


_PRECEDENCE = {Verdict.ALLOW: 0, Verdict.REQUIRE_APPROVAL: 1, Verdict.DENY: 2}


@dataclass
class PolicyRule:
    """A single rule. Unset selectors match everything."""

    name: str
    verdict: Verdict
    tools: set[str] | None = None
    agents: set[str] | None = None
    min_risk: RiskTier | None = None
    condition: Callable[[ActionRequest], bool] | None = None
    description: str = ""

    def matches(self, request: ActionRequest, risk: RiskTier) -> bool:
        if self.tools is not None and request.tool not in self.tools:
            return False
        if self.agents is not None and request.agent_id not in self.agents:
            return False
        if self.min_risk is not None and risk < self.min_risk:
            return False
        if self.condition is not None:
            try:
                return bool(self.condition(request))
            except Exception:
                # A rule that cannot be evaluated must not silently allow.
                return self.verdict != Verdict.ALLOW
        return True


@dataclass
class PolicyDecision:
    verdict: Verdict
    rule: str
    reason: str
    matched_rules: tuple[str, ...] = ()


class PolicyEngine:
    def __init__(self, rules: list[PolicyRule] | None = None, default: Verdict = Verdict.DENY):
        self.rules: list[PolicyRule] = list(rules or [])
        self.default = default

    def add(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def evaluate(self, request: ActionRequest, risk: RiskTier) -> PolicyDecision:
        matched = [r for r in self.rules if r.matches(request, risk)]
        if not matched:
            return PolicyDecision(self.default, "default", "no rule matched; default applied")
        top = max(matched, key=lambda r: _PRECEDENCE[r.verdict])
        reason = top.description or f"rule '{top.name}' matched"
        return PolicyDecision(top.verdict, top.name, reason, tuple(r.name for r in matched))

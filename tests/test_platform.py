import pytest

from gap import ActionRequest, AuditLog, GovernedRuntime, PolicyEngine, PolicyRule, RiskTier, Verdict
from gap.demo import build_runtime


def req(tool, agent="agent-1", **params):
    return ActionRequest(agent, tool, params)


# ------------------------------------------------------------------- policy
def test_default_deny_when_no_rule_matches():
    engine = PolicyEngine([])
    assert engine.evaluate(req("anything"), RiskTier.LOW).verdict == Verdict.DENY


def test_most_restrictive_verdict_wins():
    engine = PolicyEngine(
        [
            PolicyRule("allow-all", Verdict.ALLOW),
            PolicyRule("approve-medium", Verdict.REQUIRE_APPROVAL, min_risk=RiskTier.MEDIUM),
            PolicyRule("deny-high", Verdict.DENY, min_risk=RiskTier.HIGH),
        ]
    )
    assert engine.evaluate(req("t"), RiskTier.LOW).verdict == Verdict.ALLOW
    assert engine.evaluate(req("t"), RiskTier.MEDIUM).verdict == Verdict.REQUIRE_APPROVAL
    assert engine.evaluate(req("t"), RiskTier.HIGH).verdict == Verdict.DENY


def test_broken_condition_never_allows():
    engine = PolicyEngine([PolicyRule("bad", Verdict.ALLOW, condition=lambda r: r.params["missing"])])
    assert engine.evaluate(req("t"), RiskTier.LOW).verdict == Verdict.DENY


# -------------------------------------------------------------------- audit
def test_audit_chain_detects_tampering():
    log = AuditLog()
    for i in range(5):
        log.append("event", {"i": i})
    assert log.verify()
    log.entries[2]["payload"]["i"] = 99
    assert not log.verify()


def test_audit_chain_detects_deletion():
    log = AuditLog()
    for i in range(4):
        log.append("event", {"i": i})
    del log.entries[1]
    assert not log.verify()


def test_audit_persists_and_reloads(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})
    assert AuditLog.load(path).verify()


# ------------------------------------------------------------------ runtime
def test_small_refund_executes():
    rt = build_runtime()
    result = rt.submit(req("issue_refund", order_id="A100", amount=20))
    assert result.ok and "refunded" in result.output


def test_large_refund_waits_for_approval_then_executes():
    rt = build_runtime()
    result = rt.submit(req("issue_refund", order_id="A200", amount=300))
    assert result.status == "pending_approval"
    assert len(rt.approvals) == 1
    final = rt.approve(result.request_id, approver="supervisor")
    assert final.ok
    assert len(rt.approvals) == 0


def test_requester_cannot_self_approve():
    rt = build_runtime()
    result = rt.submit(req("issue_refund", agent="agent-1", order_id="A200", amount=300))
    with pytest.raises(PermissionError):
        rt.approve(result.request_id, approver="agent-1")
    assert len(rt.approvals) == 1  # still pending


def test_rejection_is_recorded():
    rt = build_runtime()
    result = rt.submit(req("issue_refund", order_id="A200", amount=300))
    rejected = rt.reject(result.request_id, approver="supervisor", reason="no damage evidence")
    assert rejected.status == "rejected"
    assert any(e["event"] == "rejected" for e in rt.audit.events_for(result.request_id))


def test_high_risk_denied():
    rt = build_runtime()
    assert rt.submit(req("delete_customer", customer_id="c-17")).status == "denied"


def test_unknown_tool_denied():
    rt = build_runtime()
    assert rt.submit(req("transfer_funds", amount=1)).status == "denied"


def test_kill_switch_blocks_everything_including_approved_actions():
    rt = build_runtime()
    pending = rt.submit(req("issue_refund", order_id="A200", amount=300))
    rt.engage_kill_switch(by="sre", reason="incident")
    assert rt.submit(req("lookup_order", order_id="A100")).status == "denied"
    assert rt.approve(pending.request_id, approver="supervisor").status == "denied"
    rt.release_kill_switch(by="sre")
    assert rt.submit(req("lookup_order", order_id="A100")).ok


def test_tool_failure_is_captured():
    rt = build_runtime()
    result = rt.submit(req("issue_refund", order_id="A100", amount=99))  # allowed but exceeds total
    assert result.status == "failed"
    assert any(e["event"] == "failed" for e in rt.audit.events_for(result.request_id))


def test_budget_limits_side_effects_but_not_reads():
    policy = PolicyEngine([PolicyRule("allow", Verdict.ALLOW)])
    rt = GovernedRuntime(policy, budget_per_agent=2)
    rt.register("write", lambda: "ok", RiskTier.LOW)
    rt.register("read", lambda: "ok", RiskTier.READ)
    assert rt.submit(req("write")).ok
    assert rt.submit(req("write")).ok
    assert rt.submit(req("write")).status == "denied"
    assert rt.submit(req("read")).ok


def test_full_run_keeps_audit_chain_valid():
    rt = build_runtime()
    rt.submit(req("lookup_order", order_id="A100"))
    p = rt.submit(req("issue_refund", order_id="A200", amount=300))
    rt.approve(p.request_id, approver="supervisor")
    rt.submit(req("delete_customer", customer_id="c-1"))
    assert rt.audit.verify()


def test_approval_rechecks_policy_before_execution():
    executed = []
    policy = PolicyEngine([PolicyRule("approval-required", Verdict.REQUIRE_APPROVAL, min_risk=RiskTier.MEDIUM)])
    rt = GovernedRuntime(policy)
    rt.register("write", lambda: executed.append("ran"), RiskTier.MEDIUM)

    pending = rt.submit(req("write"))
    assert pending.status == "pending_approval"

    policy.add(PolicyRule("emergency-deny", Verdict.DENY, tools={"write"}))
    result = rt.approve(pending.request_id, approver="supervisor")

    assert result.status == "denied"
    assert executed == []
    assert len(rt.approvals) == 0
    assert any(e["event"] == "approval_revalidated" for e in rt.audit.events_for(pending.request_id))


def test_pending_approvals_cannot_bypass_action_budget():
    policy = PolicyEngine([PolicyRule("approval-required", Verdict.REQUIRE_APPROVAL, min_risk=RiskTier.MEDIUM)])
    rt = GovernedRuntime(policy, budget_per_agent=1)
    rt.register("write", lambda: "done", RiskTier.MEDIUM)

    first = rt.submit(req("write"))
    second = rt.submit(req("write"))
    assert first.status == second.status == "pending_approval"

    assert rt.approve(first.request_id, approver="supervisor").status == "executed"
    blocked = rt.approve(second.request_id, approver="supervisor")

    assert blocked.status == "denied"
    assert "budget" in blocked.reason
    assert len(rt.approvals) == 0

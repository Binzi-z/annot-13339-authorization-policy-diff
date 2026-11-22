"""特性测试：角色循环、规则顺序、UTC 边界、重叠范围、非法配置拒绝放行。"""

from datetime import datetime, timedelta, timezone

import pytest

from authz_diff import (
    Effect,
    Policy,
    PolicyValidationError,
    ResourceScope,
    Role,
    RoleGraph,
    Rule,
    Subject,
    TimeCondition,
    TimeWindow,
    diff_policies,
    evaluate,
)
from authz_diff.scope import Trie, _Kind

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


def _rule(rid, effect, actions, scope, time=None):
    return Rule(
        rule_id=rid,
        effect=Effect(effect),
        actions=frozenset(actions),
        scope=scope,
        time=time or TimeCondition.any_time(),
    )


# ---- 角色循环 -----------------------------------------------------------

def test_role_cycle_is_detected_and_does_not_hang():
    a = Role("A", rules=[_rule("a-allow", "allow", ["read"],
                               ResourceScope.subtree("res"))],
             parents=["B"])
    b = Role("B", parents=["C"])
    c = Role("C", parents=["A"])  # A -> B -> C -> A 成环
    policy = Policy("cyclic", roles=[a, b, c],
                    subjects=[Subject("u1", ["A"])])
    cycles = RoleGraph(policy).cycles()
    assert len(cycles) == 1
    assert set(cycles[0].members) == {"A", "B", "C"}
    assert cycles[0].example[0] == cycles[0].example[-1]

    # 循环存在时评估必须终止且给出确定结果
    decision = evaluate(policy, "u1", "read", "res/x", T0)
    assert decision.allowed is True
    decision_deny = evaluate(policy, "u1", "write", "res/x", T0)
    assert decision_deny.allowed is False


def test_self_loop_is_a_cycle():
    role = Role("self", parents=["self"])
    policy = Policy("self-loop", roles=[role],
                    subjects=[Subject("u", ["self"])])
    cycles = RoleGraph(policy).cycles()
    assert len(cycles) == 1
    assert cycles[0].members == ("self",)


def test_reachable_roles_fixpoint_terminates_on_cycle():
    a = Role("A", parents=["B"])
    b = Role("B", parents=["A", "D"])
    d = Role("D")
    policy = Policy("p", roles=[a, b, d], subjects=[Subject("u", ["A"])])
    graph = RoleGraph(policy)
    assert graph.reachable_roles("A") == frozenset({"A", "B", "D"})
    assert graph.shortest_chain("A", "D") == ("A", "B", "D")


# ---- 规则顺序变化 -------------------------------------------------------

def test_rule_reorder_without_semantic_change_is_order_only():
    r1 = _rule("r1", "allow", ["read"], ResourceScope.subtree("a"))
    r2 = _rule("r2", "allow", ["read"], ResourceScope.subtree("b"))
    old = Policy("old", roles=[Role("R", rules=[r1, r2])],
                 subjects=[Subject("u", ["R"])])
    new = Policy("new", roles=[Role("R", rules=[r2, r1])],
                 subjects=[Subject("u", ["R"])])
    report = diff_policies(old, new)
    assert report.is_empty                      # 决策无差异
    assert len(report.order_only_changes) == 1  # 但顺序变化被记录


def test_deny_wins_regardless_of_rule_order():
    allow = _rule("allow", "allow", ["read"], ResourceScope.subtree("a"))
    deny = _rule("deny", "deny", ["read"], ResourceScope.exact("a/secret"))
    for ordered in ([allow, deny], [deny, allow]):
        policy = Policy(
            "p", roles=[Role("R", rules=list(ordered))],
            subjects=[Subject("u", ["R"])],
        )
        decision = evaluate(policy, "u", "read", "a/secret", T0)
        assert decision.allowed is False
        assert decision.rule_id == "deny"


# ---- UTC 边界 -----------------------------------------------------------

def test_naive_datetime_is_illegal_configuration():
    naive = datetime(2026, 1, 1, 0, 0)
    with pytest.raises(PolicyValidationError):
        TimeCondition.of(
            [TimeWindow(naive, naive + timedelta(hours=1))]
        ).validate()
    with pytest.raises(PolicyValidationError):
        Policy(
            "p",
            roles=[Role("R", rules=[
                Rule(
                    rule_id="bad",
                    effect=Effect.ALLOW,
                    actions=frozenset(["read"]),
                    scope=ResourceScope.subtree("a"),
                    time=TimeCondition(
                        (TimeWindow(naive, naive + timedelta(hours=1)),),
                    ),
                )
            ])],
            subjects=[Subject("u", ["R"])],
        )


def test_non_utc_timezone_is_rejected():
    from datetime import timezone as tz

    cst = tz(timedelta(hours=8))
    win = TimeWindow(
        datetime(2026, 1, 1, tzinfo=cst),
        datetime(2026, 1, 1, 2, tzinfo=cst),
    )
    with pytest.raises(PolicyValidationError):
        TimeCondition.of([win]).validate()


def test_zero_length_window_is_rejected():
    with pytest.raises(PolicyValidationError):
        TimeCondition.of([TimeWindow(T0, T0)]).validate()


# ---- 重叠资源范围 -------------------------------------------------------

def test_overlapping_subtree_scopes_union_and_difference():
    s1 = ResourceScope.subtree("team-a")
    s2 = ResourceScope.subtree("team-a/bucket")  # 被 s1 完全包含
    union = s1.union(s2)
    assert union.contains("team-a/anything")
    diff = s1.difference(s2)
    assert not diff.contains("team-a/bucket/obj")
    assert diff.contains("team-a/secret")


def test_scope_difference_exact_inside_subtree():
    whole = ResourceScope.subtree("team-a")
    hole = ResourceScope.exact("team-a/secret")
    remaining = whole.difference(hole)
    assert remaining.contains("team-a/bucket/obj")
    assert not remaining.contains("team-a/secret")


def test_overlapping_scope_declaration_is_illegal():
    trie = Trie()
    trie.add(("a",), _Kind.SUBTREE)
    with pytest.raises(PolicyValidationError):
        trie.add(("a", "b"), _Kind.EXACT)  # 与 SUBTREE 冲突的构造直接拒绝


# ---- 非法配置不得产出放行判断 -------------------------------------------

def test_unknown_parent_role_rejected():
    role = Role("R", parents=["ghost"])
    with pytest.raises(PolicyValidationError):
        Policy("p", roles=[role], subjects=[Subject("u", ["R"])])


def test_unknown_subject_role_rejected():
    role = Role("R")
    with pytest.raises(PolicyValidationError):
        Policy("p", roles=[role], subjects=[Subject("u", ["ghost"])])


def test_empty_action_set_rejected():
    with pytest.raises(PolicyValidationError):
        Policy(
            "p",
            roles=[Role("R", rules=[
                Rule("r", Effect.ALLOW, frozenset(),
                     ResourceScope.subtree("a"))
            ])],
            subjects=[],
        )


def test_illegal_policy_never_reaches_allow_decision():
    # 构造非法策略失败 → 调用方拿不到 Policy 对象，自然不可能得到 ALLOW
    with pytest.raises(PolicyValidationError):
        Policy(
            "bad",
            roles=[Role("R", rules=[
                Rule("r", "not-an-effect", frozenset(["read"]),
                     ResourceScope.subtree("a"))
            ])],
            subjects=[Subject("u", ["R"])],
        )


def test_naive_moment_evaluation_rejected():
    policy = Policy(
        "p",
        roles=[Role("R", rules=[
            _rule("r", "allow", ["read"], ResourceScope.subtree("a"))
        ])],
        subjects=[Subject("u", ["R"])],
    )
    with pytest.raises(PolicyValidationError):
        evaluate(policy, "u", "read", "a/x", datetime(2026, 1, 1))


# ---- 显式拒绝优先的时间语义 ---------------------------------------------

def test_time_limited_deny_punches_a_symbolic_hole():
    allow = _rule("allow-all", "allow", ["read"],
                  ResourceScope.subtree("res"))
    deny = _rule(
        "deny-morning", "deny", ["read"],
        ResourceScope.exact("res/critical"),
        TimeCondition.of([
            TimeWindow(T0, T0 + timedelta(hours=12))
        ]),
    )
    policy = Policy(
        "p", roles=[Role("R", rules=[allow, deny])],
        subjects=[Subject("u", ["R"])],
    )
    # 上午被拒
    assert evaluate(
        policy, "u", "read", "res/critical",
        T0 + timedelta(hours=6),
    ).allowed is False
    # 下午恢复允许（半开边界 12:00 即放行）
    assert evaluate(
        policy, "u", "read", "res/critical",
        T0 + timedelta(hours=12),
    ).allowed is True
    # 其他资源全时段允许
    assert evaluate(
        policy, "u", "read", "res/other", T0
    ).allowed is True

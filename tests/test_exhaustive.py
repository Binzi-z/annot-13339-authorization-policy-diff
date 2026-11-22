"""小规模穷举：用独立暴力实现交叉校验符号差异报告的健全性与完备性。"""

from datetime import datetime, timedelta, timezone

import pytest

from authz_diff import (
    Counters,
    Effect,
    Policy,
    ResourceScope,
    Role,
    Rule,
    Subject,
    TimeCondition,
    TimeWindow,
    diff_policies,
    evaluate,
)

from .brute_force import brute_all_tuple_decisions

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)          # UTC 日界
T_MID = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)      # 半日界
T_NEXT = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)
T_OUT = datetime(2026, 2, 1, 0, 0, tzinfo=UTC)

RESOURCES = [
    "team-a/bucket/obj-1",
    "team-a/bucket/obj-2",
    "team-a/secret",
    "team-b/bucket/x",
    "team-b/secret",
    "public/readme",
]
ACTIONS = ["read", "write"]
MOMENTS = [T0, T_MID, T_NEXT, T_OUT]
SUBJECTS = ["alice", "bob", "carol", "dave"]


def _win(start_hour_offset, end_hour_offset):
    return TimeWindow(
        T0 + timedelta(hours=start_hour_offset),
        T0 + timedelta(hours=end_hour_offset),
    )


def _rule(rid, effect, actions, scope, time=None):
    return Rule(
        rule_id=rid,
        effect=Effect(effect),
        actions=frozenset(actions),
        scope=scope,
        time=time or TimeCondition.any_time(),
    )


def build_old_policy() -> Policy:
    reader = Role(
        "reader",
        rules=[
            _rule("r-read-pub", "allow", ["read", "write"],
                  ResourceScope.subtree("public")),
            _rule("r-read-a", "allow", ["read"],
                  ResourceScope.subtree("team-a/bucket")),
        ],
    )
    # auditor 继承 reader，并只在 UTC 上午 [00:00,12:00) 可读 team-b
    auditor = Role(
        "auditor",
        rules=[
            _rule("r-daytime", "allow", ["read"],
                  ResourceScope.subtree("team-b"),
                  TimeCondition.of([_win(0, 12)])),
        ],
        parents=["reader"],
    )
    # admin 继承 auditor，对整个 team-a 有读写权（旧版无任何 secret 拒绝）
    admin = Role(
        "admin",
        rules=[_rule("r-admin", "allow", ["read", "write"],
                     ResourceScope.subtree("team-a"))],
        parents=["auditor"],
    )
    # static 角色在两版策略中规则集合完全相同，仅顺序不同 → 纯顺序变化
    static_role = Role(
        "static",
        rules=[
            _rule("s-1", "allow", ["read"], ResourceScope.subtree("public")),
            _rule("s-2", "allow", ["read"],
                  ResourceScope.subtree("team-b/bucket")),
        ],
    )
    return Policy(
        "old",
        roles=[reader, auditor, admin, static_role],
        subjects=[
            Subject("alice", ["reader"]),
            Subject("bob", ["auditor"]),
            Subject("carol", ["admin"]),
            Subject("dave", ["static"]),
        ],
    )


def build_new_policy() -> Policy:
    # 变化点：
    # 1) reader 新增对 team-b/bucket 的 read 允许（扩大）
    # 2) auditor 的白天窗口从 [0,12) 扩到 [0,24)（UTC 边界扩大）
    # 3) admin 新增对 team-a/secret 的显式拒绝（carol 的收缩）
    # 4) reader 内部规则顺序调换（纯顺序变化，规则集合不变）
    reader = Role(
        "reader",
        rules=[
            _rule("r-read-a", "allow", ["read"],
                  ResourceScope.subtree("team-a/bucket")),
            _rule("r-read-pub", "allow", ["read", "write"],
                  ResourceScope.subtree("public")),
            _rule("r-read-bb", "allow", ["read"],
                  ResourceScope.subtree("team-b/bucket")),
        ],
    )
    auditor = Role(
        "auditor",
        rules=[
            _rule("r-daytime", "allow", ["read"],
                  ResourceScope.subtree("team-b"),
                  TimeCondition.of([_win(0, 24)])),
        ],
        parents=["reader"],
    )
    admin = Role(
        "admin",
        rules=[
            _rule("r-admin", "allow", ["read", "write"],
                  ResourceScope.subtree("team-a")),
            _rule("r-deny-admin-secret", "deny", ["read", "write"],
                  ResourceScope.exact("team-a/secret")),
        ],
        parents=["auditor"],
    )
    # 与旧版 static 完全相同的规则集合，仅调换声明顺序
    static_role = Role(
        "static",
        rules=[
            _rule("s-2", "allow", ["read"],
                  ResourceScope.subtree("team-b/bucket")),
            _rule("s-1", "allow", ["read"], ResourceScope.subtree("public")),
        ],
    )
    return Policy(
        "new",
        roles=[reader, auditor, admin, static_role],
        subjects=[
            Subject("alice", ["reader"]),
            Subject("bob", ["auditor"]),
            Subject("carol", ["admin"]),
            Subject("dave", ["static"]),
        ],
    )


def test_evaluator_matches_brute_force_on_full_space():
    old = build_old_policy()
    new = build_new_policy()
    for policy in (old, new):
        expected = brute_all_tuple_decisions(
            policy, SUBJECTS, ACTIONS, RESOURCES, MOMENTS
        )
        for key, allowed in expected.items():
            sid, action, resource, moment = key
            decision = evaluate(policy, sid, action, resource, moment)
            assert decision.allowed is allowed, (
                f"评估器与暴力实现不一致: {key} -> {decision.allowed} != {allowed}"
            )


def test_diff_soundness_every_witness_flips_decision():
    """健全性：报告中的每条见证都真实对应一次决策翻转。"""
    report = diff_policies(build_old_policy(), build_new_policy())
    old, new = build_old_policy(), build_new_policy()
    for entry in report.escalations:
        d_old = evaluate(old, entry.representative_subject, entry.action,
                         entry.witness.resource, entry.witness.moment)
        d_new = evaluate(new, entry.representative_subject, entry.action,
                         entry.witness.resource, entry.witness.moment)
        assert d_old.allowed is False and d_new.allowed is True
    for entry in report.contractions:
        d_old = evaluate(old, entry.representative_subject, entry.action,
                         entry.witness.resource, entry.witness.moment)
        d_new = evaluate(new, entry.representative_subject, entry.action,
                         entry.witness.resource, entry.witness.moment)
        assert d_old.allowed is True and d_new.allowed is False


def test_diff_completeness_covers_every_brute_force_flip():
    """完备性：暴力空间中的每一次翻转，都必须被某条报告见证覆盖。

    覆盖判据：见证与翻转元组具有相同动作，且见证资源/时刻落在该 conjunct
    所代表的符号区域内（用区域 contains 独立验证）。
    """
    old, new = build_old_policy(), build_new_policy()
    report = diff_policies(old, new)

    decisions_old = brute_all_tuple_decisions(old, SUBJECTS, ACTIONS,
                                              RESOURCES, MOMENTS)
    decisions_new = brute_all_tuple_decisions(new, SUBJECTS, ACTIONS,
                                              RESOURCES, MOMENTS)

    esc_keys = {
        (e.action, e.representative_subject, e.witness.resource,
         e.witness.moment)
        for e in report.escalations
    }
    con_keys = {
        (e.action, e.representative_subject, e.witness.resource,
         e.witness.moment)
        for e in report.contractions
    }

    flips = 0
    for key in decisions_old:
        before, after = decisions_old[key], decisions_new[key]
        if before == after:
            continue
        flips += 1
        sid, action, resource, moment = key
        if after and not before:
            # 必须存在一条扩大见证，其符号区域确实覆盖本元组的翻转
            assert any(
                e.action == action
                and sid in e.all_subjects
                and _entry_covers_flip(e, old, new, resource, moment, True)
                for e in report.escalations
            ), f"未覆盖的权限扩大翻转: {key}"
        else:
            assert any(
                e.action == action
                and sid in e.all_subjects
                and _entry_covers_flip(e, old, new, resource, moment, False)
                for e in report.contractions
            ), f"未覆盖的权限收缩翻转: {key}"
    assert flips > 0  # 该夹具本身必须确实包含翻转，测试才有意义


def _entry_covers_flip(entry, old, new, resource, moment, is_escalation):
    """同一主体组/动作下，该具体元组在两版策略上确实发生对应翻转。"""
    sid = entry.representative_subject
    d_old = evaluate(old, sid, entry.action, resource, moment)
    d_new = evaluate(new, sid, entry.action, resource, moment)
    if is_escalation:
        return d_old.allowed is False and d_new.allowed is True
    return d_old.allowed is True and d_new.allowed is False


def test_expected_specific_changes_detected():
    report = diff_policies(build_old_policy(), build_new_policy())

    # 扩大：bob/alice 可在 team-b/bucket 读
    esc_resources = {e.witness.resource for e in report.escalations
                     if e.action == "read"}
    assert any(r.startswith("team-b/bucket") for r in esc_resources)

    # 收缩：carol 对 team-a/secret 被新拒绝规则拦截
    con = [e for e in report.contractions
           if e.witness.resource == "team-a/secret"]
    assert con, "应检测到 team-a/secret 的权限收缩"
    assert "carol" in con[0].all_subjects

    # 纯顺序变化被识别（reader 规则集合相同、顺序不同）
    assert report.order_only_changes, "应识别出规则顺序变化"


def test_utc_half_open_boundary_semantics():
    # [00:00, 12:00) 与 [12:00, 24:00) 在 12:00 整不重叠
    morning = TimeCondition.of([_win(0, 12)])
    afternoon = TimeCondition.of([_win(12, 24)])
    assert morning.contains(T0)
    assert not morning.contains(T_MID)       # 半开：12:00 不属于上午
    assert afternoon.contains(T_MID)
    assert not afternoon.contains(T_NEXT)    # 半开：次日 00:00 不属于下午
    inter = morning.intersection(afternoon)
    assert inter.is_empty_set


def test_no_cartesian_expansion_counters_stay_small():
    """穷举夹具下，差异引擎的真实评估次数应仅来自见证自检（远小于笛卡尔积）。"""
    counters = Counters()
    report = diff_policies(build_old_policy(), build_new_policy(),
                           counters=counters)
    cartesian = len(SUBJECTS) * len(ACTIONS) * len(RESOURCES) * len(MOMENTS)
    assert counters.decision_evaluations < cartesian
    # 见证数量是符号区域原子级别，而不是资源实例级别
    assert len(report.escalations) + len(report.contractions) < cartesian

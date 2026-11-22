"""合成规模化用例：证明差异引擎不展开主体 × 资源的笛卡尔积。

构造：
- S 个主体全部只绑定同一个角色（因此只有 1 个主体等价组）；
- R 个资源前缀挂在少量规则下，资源实例数量 R 远大于符号节点数；
- 新版策略扩大一个前缀的动作范围，制造一次权限扩大。

断言：
1. 差异计算耗时随规模次线性/多项式增长，且不随主体数上升；
2. 真实单请求评估次数只等于见证自检次数（个位数），
   与 S × R × action × moment 的笛卡尔积无关；
3. 每条见证都能被评估器独立复核为真实翻转。
"""

import time
from datetime import datetime, timezone

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
    diff_policies,
    evaluate,
)

UTC = timezone.utc
MOMENT = datetime(2026, 1, 1, tzinfo=UTC)


def _build_scale_policy(n_subjects: int, n_prefixes: int, *, expanded: bool):
    rules = []
    for i in range(n_prefixes):
        actions = frozenset(["read", "write"]) if expanded and i == 0 else frozenset(["read"])
        rules.append(
            Rule(
                rule_id=f"rule-{i}",
                effect=Effect.ALLOW,
                actions=actions,
                scope=ResourceScope.subtree(f"team/region-{i}"),
                time=TimeCondition.any_time(),
            )
        )
    role = Role("member", rules=rules)
    subjects = [Subject(f"user-{i:05d}", ["member"]) for i in range(n_subjects)]
    tag = "new" if expanded else "old"
    return Policy(f"scale-{tag}", roles=[role], subjects=subjects)


@pytest.mark.parametrize("n_subjects,n_prefixes", [(100, 50), (1000, 200)])
def test_no_cartesian_expansion(n_subjects, n_prefixes):
    old = _build_scale_policy(n_subjects, n_prefixes, expanded=False)
    new = _build_scale_policy(n_subjects, n_prefixes, expanded=True)

    counters = Counters()
    start = time.perf_counter()
    report = diff_policies(old, new, counters=counters)
    elapsed = time.perf_counter() - start

    cartesian = n_subjects * n_prefixes * 2 * 1

    # 1) 真实评估调用仅来自见证自检：扩大只有一个动作 × 一个前缀
    assert len(report.escalations) >= 1
    assert counters.decision_evaluations == 2 * (
        len(report.escalations) + len(report.contractions)
    )
    assert counters.decision_evaluations < 0.01 * cartesian

    # 2) 资源成员判断只发生在见证自检（每条见证评估两次），
    #    规模只随规则数线性增长，与主体数、资源实例数无关
    entries = len(report.escalations) + len(report.contractions)
    assert counters.membership_checks <= 4 * n_prefixes * max(entries, 1)
    assert counters.membership_checks < cartesian

    # 3) 每条扩大见证独立复核：旧拒绝、新放行
    for entry in report.escalations:
        d_old = evaluate(old, entry.representative_subject, entry.action,
                         entry.witness.resource, entry.witness.moment)
        d_new = evaluate(new, entry.representative_subject, entry.action,
                         entry.witness.resource, entry.witness.moment)
        assert d_old.allowed is False and d_new.allowed is True
        # 见证资源确实落在被扩大的前缀下
        assert entry.witness.resource.startswith("team/region-0")
        # 扩大动作是 write
        assert entry.action == "write"

    # 4) 所有主体在同一等价组，报告条目携带全部主体 id 但只算一次
    assert len(report.escalations[0].all_subjects) == n_subjects

    # 5) 耗时上界：千主体/两百前缀应在毫秒级完成（宽松上界，防环境抖动）
    assert elapsed < 5.0


def test_subject_count_does_not_multiply_operations():
    """主体数放大 10 倍，符号运算次数应保持不变（同等价组只算一次）。"""
    base = _build_scale_policy(100, 50, expanded=False)
    base_new = _build_scale_policy(100, 50, expanded=True)
    big = _build_scale_policy(1000, 50, expanded=False)
    big_new = _build_scale_policy(1000, 50, expanded=True)

    c1 = Counters()
    diff_policies(base, base_new, counters=c1)
    c2 = Counters()
    diff_policies(big, big_new, counters=c2)

    assert c2.region_op_count == c1.region_op_count
    assert c2.scope_op_count == c1.scope_op_count
    assert c2.decision_evaluations == c1.decision_evaluations

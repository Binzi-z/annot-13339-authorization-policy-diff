"""两版授权策略的符号差异引擎。

核心思想：不枚举主体 × 资源 × 时刻的笛卡尔积，而是

1. 按“主体角色集合”把主体归入等价类（角色集合相同则决策完全一致）；
2. 对每个等价类、每个动作，用 Trie/区间代数符号化计算有效放行区域
   （ALLOW 区域并集，再用 DENY 区域做差集剥离）；
3. 两版有效区域之差即为权限扩大/收缩，直接在符号结构上取最小见证；
4. 每个见证都用单请求评估器在两版策略上独立复核，复核失败即抛内部错误。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .counters import Counters
from .errors import InternalError, PolicyValidationError
from .evaluator import evaluate
from .model import Effect, Policy
from .region import AccessRegion, Conjunct, Provenance, Witness
from .roles import RoleGraph


@dataclass(frozen=True)
class DiffEntry:
    """一条权限变化。kind 为 escalation（扩大）或 contraction（收缩）。"""

    kind: str
    action: str
    representative_subject: str
    all_subjects: Tuple[str, ...]
    witness: Witness
    old_decision: str
    new_decision: str

    def describe(self) -> str:
        title = "权限扩大" if self.kind == "escalation" else "权限收缩"
        return (
            f"[{title}] 动作={self.action} 主体={self.representative_subject} "
            f"资源={self.witness.resource} 时刻={self.witness.moment.isoformat()} "
            f"来源={self.witness.provenance.describe()} "
            f"决策: {self.old_decision} -> {self.new_decision}"
        )


@dataclass
class DiffReport:
    policy_old: str
    policy_new: str
    escalations: List[DiffEntry] = field(default_factory=list)
    contractions: List[DiffEntry] = field(default_factory=list)
    order_only_changes: List[dict] = field(default_factory=list)
    role_cycles: Dict[str, List[tuple]] = field(default_factory=dict)
    counters: Optional[Counters] = None

    @property
    def is_empty(self) -> bool:
        return not self.escalations and not self.contractions


def diff_policies(
    old: Policy,
    new: Policy,
    *,
    verify: bool = True,
    counters: Optional[Counters] = None,
) -> DiffReport:
    for label, policy in (("旧版", old), ("新版", new)):
        if not isinstance(policy, Policy):
            raise PolicyValidationError(f"{label}策略对象非法，拒绝产出差异报告")

    counters = counters or Counters()
    with counters:
        report = DiffReport(old.name, new.name, counters=counters)

        report.role_cycles = {
            old.name: [c.example for c in RoleGraph(old).cycles()],
            new.name: [c.example for c in RoleGraph(new).cycles()],
        }
        report.order_only_changes = _detect_order_only_changes(old, new)

        actions = sorted(old.all_actions | new.all_actions)
        groups_old = _subject_groups(old)
        groups_new = _subject_groups(new)
        all_group_keys = sorted(set(groups_old) | set(groups_new))

        for key in all_group_keys:
            subjects = sorted(
                set(groups_old.get(key, ())) | set(groups_new.get(key, ()))
            )
            representative = subjects[0]
            entry_roles = list(key)
            for action in actions:
                region_old = _effective_region(old, entry_roles, action, counters)
                region_new = _effective_region(new, entry_roles, action, counters)

                gained = region_new.difference(region_old, counters)
                lost = region_old.difference(region_new, counters)

                for region, kind, container in (
                    (gained, "escalation", report.escalations),
                    (lost, "contraction", report.contractions),
                ):
                    for witness in region.witnesses():
                        entry = _make_entry(
                            kind, action, representative, tuple(subjects),
                            witness, old, new, verify, counters,
                        )
                        container.append(entry)

    return report


# ---- 主体等价分组 -------------------------------------------------------

def _subject_groups(policy: Policy) -> Dict[Tuple[str, ...], Tuple[str, ...]]:
    groups: Dict[frozenset, List[str]] = {}
    for subject in policy.subjects:
        groups.setdefault(frozenset(subject.roles), []).append(subject.subject_id)
    return {
        tuple(sorted(role_set)): tuple(sorted(ids))
        for role_set, ids in groups.items()
    }


# ---- 符号化有效放行区域 -------------------------------------------------

def _effective_region(
    policy: Policy,
    entry_roles: List[str],
    action: str,
    counters: Counters,
) -> AccessRegion:
    graph = RoleGraph(policy)
    allows: List[Conjunct] = []
    denies: List[Conjunct] = []
    for item in graph.ordered_rules(entry_roles):
        rule = item.rule
        if action not in rule.actions:
            continue
        provenance = Provenance(rule.rule_id, item.role_chain)
        conjunct = Conjunct(rule.scope, rule.time, provenance)
        if rule.effect is Effect.DENY:
            denies.append(conjunct)
        else:
            allows.append(conjunct)

    allow_region = AccessRegion(())
    for conjunct in allows:
        allow_region = allow_region.union(AccessRegion([conjunct]), counters)

    if not denies:
        return allow_region

    deny_region = AccessRegion(())
    for conjunct in denies:
        deny_region = deny_region.union(AccessRegion([conjunct]), counters)

    # 显式拒绝优先：有效放行 = 允许区域 - 拒绝区域
    return allow_region.difference(deny_region, counters)


# ---- 见证构造与独立复核 -------------------------------------------------

def _make_entry(
    kind: str,
    action: str,
    representative: str,
    all_subjects: Tuple[str, ...],
    witness: Witness,
    old: Policy,
    new: Policy,
    verify: bool,
    counters: Counters,
) -> DiffEntry:
    d_old = evaluate(
        old, representative, action, witness.resource, witness.moment, counters
    )
    d_new = evaluate(
        new, representative, action, witness.resource, witness.moment, counters
    )
    if verify:
        if kind == "escalation" and not (not d_old.allowed and d_new.allowed):
            raise InternalError(
                f"权限扩大见证复核失败: {witness} {d_old} -> {d_new}"
            )
        if kind == "contraction" and not (d_old.allowed and not d_new.allowed):
            raise InternalError(
                f"权限收缩见证复核失败: {witness} {d_old} -> {d_new}"
            )
    return DiffEntry(
        kind=kind,
        action=action,
        representative_subject=representative,
        all_subjects=all_subjects,
        witness=witness,
        old_decision="ALLOW" if d_old.allowed else "DENY",
        new_decision="ALLOW" if d_new.allowed else "DENY",
    )


# ---- 规则顺序变化检测 ---------------------------------------------------

def _detect_order_only_changes(old: Policy, new: Policy) -> List[dict]:
    """找出角色集合未变但规则聚合顺序变化的主体；是否纯顺序变化由调用方
    结合最终决策差异判断（决策无差异时即为纯顺序变化）。"""
    changes: List[dict] = []
    old_groups = _subject_groups(old)
    new_groups = _subject_groups(new)
    for key in sorted(set(old_groups) & set(new_groups)):
        sig_old = RoleGraph(old).rule_order_signature(list(key))
        sig_new = RoleGraph(new).rule_order_signature(list(key))
        if sig_old != sig_new and set(sig_old) == set(sig_new):
            changes.append(
                {
                    "role_group": key,
                    "subjects": new_groups[key],
                    "old_order": sig_old,
                    "new_order": sig_new,
                }
            )
    return changes

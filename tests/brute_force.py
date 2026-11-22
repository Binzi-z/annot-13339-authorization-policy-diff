"""独立的暴力参考实现（仅供测试对照，不参与生产路径）。

刻意用最直白的集合/递归方式重新实现一遍决策语义，与生产引擎
（roles.py / evaluator.py / diff.py 的 Trie 与 DNF 代数）不共享任何算法代码，
这样两者一致才能为符号差异报告提供独立交叉验证。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from authz_diff.model import Effect, Policy


@dataclass(frozen=True)
class BruteDecision:
    allowed: bool
    rule_id: Optional[str] = None


def _all_rules(policy: Policy, entry_roles: List[str]):
    """DFS 聚合规则，循环由 visited 截断；返回 (rule, chain)。"""
    out = []
    visited: Set[str] = set()

    def walk(name: str, chain: Tuple[str, ...]):
        if name in visited:
            return
        visited.add(name)
        role = policy.roles[name]
        for rule in role.rules:
            out.append((rule, chain + (name,)))
        for parent in role.parents:
            walk(parent, chain + (name,))

    for entry in entry_roles:
        walk(entry, ())
    return out


def brute_decide(
    policy: Policy,
    subject_id: str,
    action: str,
    resource: str,
    moment,
) -> BruteDecision:
    subject = next((s for s in policy.subjects if s.subject_id == subject_id), None)
    if subject is None:
        return BruteDecision(False)

    segments = tuple(p for p in resource.strip("/").split("/") if p)
    allow: Optional[str] = None
    for rule, _chain in _all_rules(policy, subject.roles):
        if action not in rule.actions:
            continue
        if not _brute_scope_contains(rule, segments):
            continue
        if not rule.time.contains(moment):
            continue
        if rule.effect is Effect.DENY:
            return BruteDecision(False, rule.rule_id)
        if allow is None:
            allow = rule.rule_id
    return BruteDecision(allow is not None, allow)


def _brute_scope_contains(rule, segments: Tuple[str, ...]) -> bool:
    """直接遍历 Trie 标记做成员判断（与生产 contains 独立写法）。"""
    for atom in rule.scope.atoms:
        if _trie_has(atom.include, segments) and not _trie_has(
            atom.exclude, segments
        ):
            return True
    return False


def _trie_has(trie, segments: Tuple[str, ...]) -> bool:
    node = trie
    from authz_diff.scope import _Kind

    if node.marker is _Kind.SUBTREE:
        return True
    for seg in segments:
        child = node.children.get(seg)
        if child is None:
            return False
        node = child
        if node.marker is _Kind.SUBTREE:
            return True
    return node.marker is not None


def brute_all_tuple_decisions(
    policy: Policy,
    subject_ids: List[str],
    actions: List[str],
    resources: List[str],
    moments: List,
) -> Dict[tuple, bool]:
    """穷举整个判定空间，返回 (subject, action, resource, moment) -> allowed。"""
    result: Dict[tuple, bool] = {}
    for sid in subject_ids:
        for action in actions:
            for resource in resources:
                for moment in moments:
                    decision = brute_decide(policy, sid, action, resource, moment)
                    result[(sid, action, resource, moment)] = decision.allowed
    return result

"""符号访问区域：资源范围 × 时段条件 的 DNF 及其代数。

一个 ``AccessRegion`` 是若干 ``Conjunct`` 的并；每个 conjunct 是
“资源范围 ∩ 时间窗”，并携带来源信息（由哪些角色的哪些规则产生）。
差异计算只操作这些符号结构，从不枚举具体资源。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .counters import Counters
from .scope import ResourceScope
from .timecond import TimeCondition


@dataclass(frozen=True)
class Provenance:
    """一条符号区域的最小来源：触发的规则 id 与最短角色继承链。"""

    rule_id: str
    role_chain: Tuple[str, ...]

    def describe(self) -> str:
        return f"规则 {self.rule_id}（继承链: {' -> '.join(self.role_chain)}）"


@dataclass(frozen=True)
class Conjunct:
    scope: ResourceScope
    time: TimeCondition
    provenance: Provenance

    @property
    def is_empty(self) -> bool:
        return self.scope.is_empty or self.time.is_empty_set


class AccessRegion:
    def __init__(self, conjuncts: Sequence[Conjunct] = ()):
        self.conjuncts: Tuple[Conjunct, ...] = tuple(
            c for c in conjuncts if not c.is_empty
        )

    @staticmethod
    def empty() -> "AccessRegion":
        return AccessRegion(())

    @property
    def is_empty(self) -> bool:
        return not self.conjuncts

    def contains(self, path: str, moment,
                 counters: Optional[Counters] = None) -> bool:
        return any(
            c.scope.contains(path, counters) and c.time.contains(moment)
            for c in self.conjuncts
        )

    def witness(self) -> Optional["Witness"]:
        """取最小见证：字典序最小资源 + 最早 UTC 时刻。"""
        candidates = self.witnesses()
        if not candidates:
            return None
        return min(candidates, key=lambda w: (w.resource, w.moment))

    def witnesses(self) -> List["Witness"]:
        """每个符号 conjunct 产出一条最小见证（按资源/时刻去重）。"""
        out: List[Witness] = []
        seen: set = set()
        for conj in self.conjuncts:
            path = conj.scope.witness()
            if path is None:
                continue
            moment = conj.time.earliest_moment()
            if moment is None:
                continue
            witness = Witness(path, moment, conj.provenance)
            key = (path, moment)
            if key not in seen:
                seen.add(key)
                out.append(witness)
        return out

    # ---- 代数 -----------------------------------------------------------

    def union(self, other: "AccessRegion",
              counters: Optional[Counters] = None) -> "AccessRegion":
        Counters.bump_region()
        return AccessRegion(self.conjuncts + other.conjuncts)

    def intersection(self, other: "AccessRegion",
                     counters: Optional[Counters] = None) -> "AccessRegion":
        Counters.bump_region()
        out: List[Conjunct] = []
        for a in self.conjuncts:
            for b in other.conjuncts:
                scope = a.scope.intersection(b.scope)
                if scope.is_empty:
                    continue
                time = a.time.intersection(b.time)
                if time.is_empty_set:
                    continue
                out.append(
                    Conjunct(scope, time, _merge_prov(a.provenance, b.provenance))
                )
        return AccessRegion(out)

    def difference(self, other: "AccessRegion",
                   counters: Optional[Counters] = None) -> "AccessRegion":
        """self - other。

        对 other 的每个 conjunct 依次做 DNF 差集；展开规模只与两侧
        conjunct 数量（规则/前缀数量）有关，与资源数量无关。
        """
        if other.is_empty:
            return AccessRegion(self.conjuncts)
        Counters.bump_region()
        current = list(self.conjuncts)
        for b in other.conjuncts:
            nxt: List[Conjunct] = []
            for a in current:
                nxt.extend(_subtract_conjunct(a, b))
            current = nxt
        return AccessRegion(current)


def _subtract_conjunct(a: Conjunct, b: Conjunct) -> List[Conjunct]:
    """单个 conjunct 之间的差集：a - b = (Sa × Ta) \\ (Sb × Tb)。

    资源与时间两个维度的差集代数都已闭合，可直接组合：
      (Sa × Ta) \\ (Sb × Tb)
        = (Sa \\ Sb) × Ta                 （资源落在 b 之外，时间不变）
          ∪ (Sa ∩ Sb) × (Ta \\ Tb)        （资源重叠，按时段剥离）
    """
    scope_overlap = a.scope.intersection(b.scope)
    if scope_overlap.is_empty:
        return [a]  # 资源不相交，b 无法扣除 a 的任何部分

    result: List[Conjunct] = []

    scope_outside = a.scope.difference(b.scope)
    if not scope_outside.is_empty:
        result.append(Conjunct(scope_outside, a.time, a.provenance))

    time_remaining = a.time.difference(b.time)
    if not time_remaining.is_empty_set:
        result.append(Conjunct(scope_overlap, time_remaining, a.provenance))
    return result


def _merge_prov(a: Provenance, b: Provenance) -> Provenance:
    """交/并运算时合并来源：保留较短的角色链与对应规则。"""
    if len(a.role_chain) <= len(b.role_chain):
        return Provenance(a.rule_id, a.role_chain)
    return Provenance(b.rule_id, b.role_chain)


@dataclass(frozen=True)
class Witness:
    """可独立复核的最小见证：一个具体资源 + 一个具体 UTC 时刻 + 来源。"""

    resource: str
    moment: object
    provenance: Provenance

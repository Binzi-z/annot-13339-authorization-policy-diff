"""角色继承图：循环检测、固定点可达、最短继承链与规则聚合顺序。"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .model import Policy, Rule


@dataclass
class CycleInfo:
    """检测到的角色继承循环。members 是构成 SCC 的角色集合，example 是一条示例环。"""

    members: Tuple[str, ...]
    example: Tuple[str, ...]


@dataclass
class _OrderedRule:
    rule: Rule
    role_chain: Tuple[str, ...]
    order_index: int


class RoleGraph:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.roles = policy.roles
        self._cycles: Optional[List[CycleInfo]] = None
        self._reach_cache: Dict[str, frozenset] = {}
        self._shortest_cache: Dict[Tuple[str, str], Tuple[str, ...]] = {}

    # ---- 循环检测（Tarjan SCC） -----------------------------------------

    def cycles(self) -> List[CycleInfo]:
        if self._cycles is not None:
            return self._cycles
        index_counter = [0]
        stack: List[str] = []
        on_stack: Dict[str, bool] = {}
        indices: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        result: List[CycleInfo] = []

        def strongconnect(v: str) -> None:
            indices[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True
            for w in self.roles[v].parents:
                if w not in indices:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack.get(w):
                    lowlink[v] = min(lowlink[v], indices[w])
            if lowlink[v] == indices[v]:
                component: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == v:
                        break
                # 单点 SCC 只有存在自环才算循环
                if len(component) > 1 or v in self.roles[v].parents:
                    result.append(
                        CycleInfo(
                            members=tuple(sorted(component)),
                            example=self._example_cycle(component),
                        )
                    )

        for name in self.roles:
            if name not in indices:
                strongconnect(name)
        self._cycles = result
        return result

    def _example_cycle(self, component: List[str]) -> Tuple[str, ...]:
        members = set(component)
        start = sorted(component)[0]
        # BFS 在 SCC 内部找一条回到 start 的路径作为示例环
        prev: Dict[str, str] = {}
        queue = deque([start])
        seen = {start}
        target: Optional[str] = None
        while queue:
            node = queue.popleft()
            for parent in self.roles[node].parents:
                if parent not in members:
                    continue
                if parent == start and node != start:
                    target = node
                    break
                if parent not in seen:
                    seen.add(parent)
                    prev[parent] = node
                    queue.append(parent)
            if target is not None:
                break
        if target is None and start in self.roles[start].parents:
            return (start, start)
        if target is None:
            return tuple(sorted(component))
        path = [target]
        while path[-1] != start:
            path.append(prev[path[-1]])
        path.reverse()
        return tuple(path + [start])

    # ---- 固定点可达 -----------------------------------------------------

    def reachable_roles(self, start: str) -> frozenset:
        """从 start 出发沿继承边可达的全部角色（含自身），固定点闭包。

        循环存在时由 visited 集合保证终止，每个角色只处理一次。
        """
        if start in self._reach_cache:
            return self._reach_cache[start]
        seen = {start}
        queue = deque([start])
        while queue:
            node = queue.popleft()
            for parent in self.roles[node].parents:
                if parent not in seen:
                    seen.add(parent)
                    queue.append(parent)
        result = frozenset(seen)
        self._reach_cache[start] = result
        return result

    def shortest_chain(self, start: str, target: str) -> Optional[Tuple[str, ...]]:
        """BFS 最短继承链（含两端），循环安全。"""
        key = (start, target)
        if key in self._shortest_cache:
            return self._shortest_cache[key]
        prev: Dict[str, str] = {}
        queue = deque([start])
        seen = {start}
        found = False
        while queue and not found:
            node = queue.popleft()
            if node == target:
                found = True
                break
            for parent in self.roles[node].parents:
                if parent not in seen:
                    seen.add(parent)
                    prev[parent] = node
                    queue.append(parent)
        if target not in seen:
            self._shortest_cache[key] = None
            return None
        path = [target]
        while path[-1] != start:
            path.append(prev[path[-1]])
        path.reverse()
        chain = tuple(path)
        self._shortest_cache[key] = chain
        return chain

    # ---- 规则聚合（保持声明顺序，循环安全） ------------------------------

    def ordered_rules(self, entry_roles: List[str]) -> List[_OrderedRule]:
        """按继承展开规则。

        顺序语义：对每个入口角色做深度优先遍历，先输出该角色自身规则，
        再按 parents 声明顺序递归；循环由 visiting/visited 集合截断。
        同一条规则只在首次访问时输出，因此规则顺序变化可被检测、
        角色循环也不会导致无限展开。
        """
        out: List[_OrderedRule] = []
        visited: set = set()
        order = [0]

        def walk(role_name: str, chain: Tuple[str, ...]) -> None:
            if role_name in visited:
                return
            visited.add(role_name)
            role = self.roles[role_name]
            for rule in role.rules:
                out.append(
                    _OrderedRule(
                        rule=rule,
                        role_chain=chain + (role_name,),
                        order_index=order[0],
                    )
                )
                order[0] += 1
            for parent in role.parents:
                walk(parent, chain + (role_name,))

        for entry in entry_roles:
            walk(entry, ())
        return out

    def rule_order_signature(self, entry_roles: List[str]) -> Tuple[str, ...]:
        """规则顺序指纹：仅由规则 id 按聚合顺序组成，用于顺序变化检测。"""
        return tuple(item.rule.rule_id for item in self.ordered_rules(entry_roles))

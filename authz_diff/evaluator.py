"""单请求访问决策评估器（拒绝优先，默认拒绝）。

评估流程：
1. 策略在构造时已完成整体合法性校验，非法策略根本无法进入这里；
2. 聚合主体可达角色的全部规则（循环安全、保持声明顺序）；
3. 任一匹配的 DENY 规则立即拒绝（显式拒绝优先）；
4. 否则存在匹配的 ALLOW 规则才放行；
5. 没有任何规则匹配 → 默认拒绝。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .counters import Counters
from .errors import PolicyValidationError
from .model import Effect, Policy
from .roles import RoleGraph
from .scope import split_path


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule_id: Optional[str] = None
    role_chain: Optional[tuple] = None


def evaluate(
    policy: Policy,
    subject_id: str,
    action: str,
    resource: str,
    moment: datetime,
    counters: Optional[Counters] = None,
) -> Decision:
    # 入口防御：任何非法配置都直接报错，绝不产出放行判断
    if not isinstance(policy, Policy):
        raise PolicyValidationError("评估入口收到非法策略对象")
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise PolicyValidationError("评估时刻必须是 UTC aware datetime")

    subject = next((s for s in policy.subjects if s.subject_id == subject_id), None)
    if subject is None:
        return Decision(False, f"主体 {subject_id!r} 不存在（默认拒绝）")

    if counters is not None:
        counters.decision_evaluations += 1

    graph = RoleGraph(policy)
    segments = split_path(resource)

    allow_match: Optional[tuple] = None
    for item in graph.ordered_rules(subject.roles):
        rule = item.rule
        if action not in rule.actions:
            continue
        if not rule.scope.contains("/".join(segments), counters):
            continue
        if not rule.time.contains(moment):
            continue
        if rule.effect is Effect.DENY:
            # 显式拒绝立即生效，顺序再靠后也压过 ALLOW
            return Decision(
                False,
                f"被显式拒绝规则 {rule.rule_id!r} 拦截",
                rule.rule_id,
                item.role_chain,
            )
        if allow_match is None:
            allow_match = (rule.rule_id, item.role_chain)

    if allow_match is not None:
        return Decision(
            True,
            f"由允许规则 {allow_match[0]!r} 放行",
            allow_match[0],
            allow_match[1],
        )
    return Decision(False, "无匹配的允许规则（默认拒绝）")

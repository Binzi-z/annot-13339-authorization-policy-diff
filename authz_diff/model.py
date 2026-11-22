"""核心数据模型与策略合法性校验。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Sequence

from .errors import PolicyValidationError
from .scope import ResourceScope
from .timecond import TimeCondition


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Rule:
    """单条授权规则。

    - actions: 该规则适用的动作集合（非空）
    - scope:   资源范围（前缀 Trie 规范化后的 ResourceScope）
    - time:    时段条件；TimeCondition.any() 表示不受时间限制
    """

    rule_id: str
    effect: Effect
    actions: frozenset
    scope: ResourceScope
    time: TimeCondition = field(default_factory=lambda: TimeCondition.any())

    def __post_init__(self):
        if not isinstance(self.effect, Effect):
            try:
                object.__setattr__(self, "effect", Effect(self.effect))
            except ValueError:
                pass  # 交由 validate 统一报错

    def validate(self, errors: List[str]) -> None:
        prefix = f"规则 {self.rule_id!r}"
        if not isinstance(self.rule_id, str) or not self.rule_id:
            errors.append("规则 id 必须是非空字符串")
        if not isinstance(self.effect, Effect):
            errors.append(f"{prefix} 的 effect 非法: {self.effect!r}")
        if not self.actions or not all(isinstance(a, str) and a for a in self.actions):
            errors.append(f"{prefix} 的动作集合必须是非空字符串集合")
        if not isinstance(self.scope, ResourceScope):
            errors.append(f"{prefix} 的资源范围类型非法")
        else:
            try:
                self.scope.validate()
            except PolicyValidationError as exc:
                errors.extend(f"{prefix}: {e}" for e in exc.errors)
        if not isinstance(self.time, TimeCondition):
            errors.append(f"{prefix} 的时段条件类型非法")
        else:
            try:
                self.time.validate()
            except PolicyValidationError as exc:
                errors.extend(f"{prefix}: {e}" for e in exc.errors)


@dataclass
class Role:
    """角色：自带规则 + 继承的父角色。parents 顺序即规则继承顺序。"""

    name: str
    rules: List[Rule] = field(default_factory=list)
    parents: List[str] = field(default_factory=list)

    def validate(self, errors: List[str]) -> None:
        if not isinstance(self.name, str) or not self.name:
            errors.append("角色名必须是非空字符串")
        for rule in self.rules:
            rule.validate(errors)
        if not all(isinstance(p, str) and p for p in self.parents):
            errors.append(f"角色 {self.name!r} 的父角色名必须是非空字符串")


@dataclass
class Subject:
    """访问主体：通过角色集合获得权限。"""

    subject_id: str
    roles: List[str]

    def validate(self, errors: List[str]) -> None:
        if not isinstance(self.subject_id, str) or not self.subject_id:
            errors.append("主体 id 必须是非空字符串")
        if not self.roles or not all(isinstance(r, str) and r for r in self.roles):
            errors.append(
                f"主体 {self.subject_id!r} 必须至少绑定一个非空角色名"
            )


class Policy:
    """一版完整授权策略。

    构造时立即做整体合法性校验，非法时抛出 PolicyValidationError（聚合全部错误），
    因此任何非法策略都无法进入评估/差异流程，更不可能产出放行判断。
    """

    def __init__(
        self,
        name: str,
        roles: Sequence[Role],
        subjects: Sequence[Subject],
        *,
        reject_cycles: bool = False,
    ):
        self.name = name
        self.roles: Dict[str, Role] = {}
        self.subjects: List[Subject] = list(subjects)
        self.reject_cycles = reject_cycles
        errors: List[str] = []

        if not isinstance(name, str) or not name:
            errors.append("策略名必须是非空字符串")

        seen_rule_ids: set = set()
        for role in roles:
            if not isinstance(role, Role):
                errors.append(f"角色条目类型非法: {role!r}")
                continue
            role.validate(errors)
            if role.name in self.roles:
                errors.append(f"角色重复定义: {role.name!r}")
            self.roles[role.name] = role
            for rule in role.rules:
                if rule.rule_id in seen_rule_ids:
                    errors.append(f"规则 id 在策略内重复: {rule.rule_id!r}")
                seen_rule_ids.add(rule.rule_id)

        # 父角色引用完整性
        for role in self.roles.values():
            for parent in role.parents:
                if parent not in self.roles:
                    errors.append(
                        f"角色 {role.name!r} 继承了不存在的角色 {parent!r}"
                    )

        seen_subjects: set = set()
        for subject in self.subjects:
            if not isinstance(subject, Subject):
                errors.append(f"主体条目类型非法: {subject!r}")
                continue
            subject.validate(errors)
            if subject.subject_id in seen_subjects:
                errors.append(f"主体重复定义: {subject.subject_id!r}")
            seen_subjects.add(subject.subject_id)
            for role_name in subject.roles:
                if role_name not in self.roles:
                    errors.append(
                        f"主体 {subject.subject_id!r} 绑定了不存在的角色 {role_name!r}"
                    )

        if errors:
            raise PolicyValidationError(errors)

    @property
    def all_actions(self) -> frozenset:
        actions: set = set()
        for role in self.roles.values():
            for rule in role.rules:
                actions.update(rule.actions)
        return frozenset(actions)

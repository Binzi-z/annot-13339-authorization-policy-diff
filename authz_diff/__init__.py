"""跨团队授权策略比较工具（符号化访问决策差异引擎）。

模块划分：
- model:      规则 / 角色 / 主体 / 策略等数据模型与策略合法性校验
- scope:      资源前缀 Trie、包含/排除代数、重叠资源范围处理
- timecond:   UTC 半开时间窗与区间代数
- region:     符号访问区域（资源 × 时间）及其并/交/差代数
- roles:      角色继承图、循环检测、固定点可达与最短继承链
- evaluator:  单请求访问决策（显式拒绝优先，默认拒绝）
- diff:       两版策略的符号差异引擎与最小可复核见证
- counters:   运算量统计，用于规模化论证（证明不展开笛卡尔积）
"""

from .model import Effect, Rule, Role, Subject, Policy, PolicyValidationError
from .timecond import TimeWindow, TimeCondition
from .scope import ResourceScope, ScopeAtom
from .region import AccessRegion, Witness, Provenance
from .roles import RoleGraph, CycleInfo
from .evaluator import evaluate
from .diff import diff_policies, DiffEntry, DiffReport
from .counters import Counters

__all__ = [
    "Effect",
    "Rule",
    "Role",
    "Subject",
    "Policy",
    "PolicyValidationError",
    "TimeWindow",
    "TimeCondition",
    "ResourceScope",
    "ScopeAtom",
    "AccessRegion",
    "Witness",
    "Provenance",
    "RoleGraph",
    "CycleInfo",
    "evaluate",
    "diff_policies",
    "DiffEntry",
    "DiffReport",
    "Counters",
]

"""运算量统计计数器。

差异引擎全程做符号运算，不枚举具体主体/资源组合。规模化测试通过这些计数器
断言：决策评估次数与资源成员判断次数保持在与策略规模多项式相关的低水平，
而不是主体数 × 资源数的笛卡尔积。

底层 Trie/区间代数不感知单次 diff 的 Counters 实例，因此用线程局部的
“活动计数器”接收埋点；diff_policies 执行期间把传入的 Counters 注册为活动实例。
"""

import threading
from dataclasses import dataclass


@dataclass
class Counters:
    decision_evaluations: int = 0      # 真正调用单请求评估器的次数（仅见证自检）
    membership_checks: int = 0         # 资源路径成员判断次数
    scope_op_count: int = 0            # Trie 级代数运算次数
    region_op_count: int = 0           # 访问区域代数运算次数

    _local = threading.local()

    def __enter__(self):
        previous = getattr(self._local, "active", None)
        self._previous = previous
        self._local.active = self
        return self

    def __exit__(self, exc_type, exc, tb):
        self._local.active = getattr(self, "_previous", None)
        return False

    @classmethod
    def _active(cls) -> "Counters":
        active = getattr(cls._local, "active", None)
        return active

    @classmethod
    def bump_scope(cls) -> None:
        active = cls._active()
        if active is not None:
            active.scope_op_count += 1

    @classmethod
    def bump_region(cls) -> None:
        active = cls._active()
        if active is not None:
            active.region_op_count += 1

    def as_dict(self) -> dict:
        return {
            "decision_evaluations": self.decision_evaluations,
            "membership_checks": self.membership_checks,
            "scope_op_count": self.scope_op_count,
            "region_op_count": self.region_op_count,
        }

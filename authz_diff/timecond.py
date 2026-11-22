"""UTC 时段条件与区间代数。

所有时间窗都是半开区间 ``[start, end)``，且必须是带 UTC 时区的 ``datetime``。
采用半开区间使两个相邻窗在边界时刻的归属无歧义：
``[00:00, 12:00)`` 与 ``[12:00, 24:00)`` 在 12:00:00 这一刻不会重叠，
从而可以精确处理 UTC 日界 / 整点边界。

两种表示，差集运算对二者都闭合：

- 受限集合（``unrestricted=False``）：仅在 ``windows`` 这些半开窗内生效；
- 全时间轴带排除（``unrestricted=True``）：任意时刻生效，但 ``exclusions``
  中的窗口被挖掉。这样“全时段允许被某时段的显式拒绝剥离”可以被精确
  符号化，无需枚举时刻，也不会丢失排除包络之外的时间。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from .errors import PolicyValidationError


def _require_utc(dt: datetime, errors: List[str], label: str) -> None:
    if not isinstance(dt, datetime):
        errors.append(f"{label} 必须是 datetime 实例")
        return
    if dt.tzinfo is None:
        errors.append(f"{label} 缺少时区信息（只接受 UTC aware datetime）")
    elif dt.utcoffset() != timezone.utc.utcoffset(None):
        errors.append(f"{label} 不是 UTC 时间（偏移={dt.utcoffset()}）")


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    def validate(self, errors: List[str]) -> None:
        _require_utc(self.start, errors, "时间窗起点")
        _require_utc(self.end, errors, "时间窗终点")
        if (
            isinstance(self.start, datetime)
            and isinstance(self.end, datetime)
            and self.start.tzinfo is not None
            and self.end.tzinfo is not None
        ):
            if self.end <= self.start:
                errors.append(
                    f"时间窗终点必须晚于起点: [{self.start.isoformat()}, "
                    f"{self.end.isoformat()})"
                )


def _merge_windows(windows: Sequence[TimeWindow]) -> Tuple[TimeWindow, ...]:
    ordered = sorted(windows, key=lambda w: w.start)
    merged: List[TimeWindow] = []
    for win in ordered:
        if merged and win.start <= merged[-1].end:
            # 半开区间：相邻（win.start == prev.end）也可安全合并
            if win.end > merged[-1].end:
                merged[-1] = TimeWindow(merged[-1].start, win.end)
        else:
            merged.append(win)
    return tuple(merged)


def _intersect_windows(
    a: Sequence[TimeWindow], b: Sequence[TimeWindow]
) -> Tuple[TimeWindow, ...]:
    result: List[TimeWindow] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i].start, b[j].start)
        hi = min(a[i].end, b[j].end)
        if lo < hi:
            result.append(TimeWindow(lo, hi))
        if a[i].end <= b[j].end:
            i += 1
        else:
            j += 1
    return tuple(result)


@dataclass(frozen=True)
class TimeCondition:
    """时间集合：受限窗口并集，或全时间轴减去排除窗。"""

    windows: Tuple[TimeWindow, ...] = ()
    unrestricted: bool = False
    exclusions: Tuple[TimeWindow, ...] = ()

    # ---- 构造与校验 -----------------------------------------------------

    @staticmethod
    def any_time() -> "TimeCondition":
        return TimeCondition((), unrestricted=True, exclusions=())

    # 兼容 model.py 中的工厂命名
    @staticmethod
    def any() -> "TimeCondition":
        return TimeCondition.any_time()

    @staticmethod
    def of(windows: Sequence[TimeWindow]) -> "TimeCondition":
        if not windows:
            raise PolicyValidationError("受限时间条件至少需要一个时间窗")
        return TimeCondition(tuple(windows), unrestricted=False)

    def __post_init__(self):
        if self.unrestricted:
            object.__setattr__(self, "windows", ())
            object.__setattr__(
                self, "exclusions", _merge_windows(self.exclusions)
            )
        elif self.windows:
            object.__setattr__(self, "windows", _merge_windows(self.windows))
            object.__setattr__(self, "exclusions", ())

    def validate(self) -> None:
        errors: List[str] = []
        if self.unrestricted and self.windows:
            errors.append("不受限时间条件不能同时携带生效窗口")
        for win in self.windows:
            win.validate(errors)
        for win in self.exclusions:
            win.validate(errors)
        if errors:
            raise PolicyValidationError(errors)

    @property
    def is_unrestricted(self) -> bool:
        return self.unrestricted

    @property
    def is_empty_set(self) -> bool:
        """受限且没有任何有效窗 → 空集合（任何时刻都不生效）。"""
        return not self.unrestricted and not self.windows

    def contains(self, moment: datetime) -> bool:
        if self.unrestricted:
            return not any(
                w.start <= moment < w.end for w in self.exclusions
            )
        return any(w.start <= moment < w.end for w in self.windows)

    # ---- 代数运算 -------------------------------------------------------

    def union(self, other: "TimeCondition") -> "TimeCondition":
        if self.unrestricted and other.unrestricted:
            # (U\\E1) ∪ (U\\E2) = U \\ (E1 ∩ E2)
            common = _intersect_windows(self.exclusions, other.exclusions)
            return TimeCondition((), unrestricted=True, exclusions=common)
        if self.unrestricted:
            # U\\E1 ∪ W2：仍为全时间轴，排除集缩小为 E1 \\ W2
            remaining = self._subtract_window_sets(self.exclusions, other.windows)
            return TimeCondition((), unrestricted=True, exclusions=remaining)
        if other.unrestricted:
            return other.union(self)
        return TimeCondition(tuple(self.windows) + tuple(other.windows))

    def intersection(self, other: "TimeCondition") -> "TimeCondition":
        if self.unrestricted and other.unrestricted:
            merged = _merge_windows(tuple(self.exclusions) + tuple(other.exclusions))
            return TimeCondition((), unrestricted=True, exclusions=merged)
        if self.unrestricted:
            # (U\\E1) ∩ W2 = W2 \\ E1
            kept = self._subtract_window_sets(other.windows, self.exclusions)
            return TimeCondition(kept)
        if other.unrestricted:
            return other.intersection(self)
        return TimeCondition(_intersect_windows(self.windows, other.windows))

    def difference(self, other: "TimeCondition") -> "TimeCondition":
        """self - other，对全时间轴与受限集合均闭合且精确。"""
        if other.unrestricted:
            # 减去 U\\E2：self 中只有落在 E2 内的部分可能保留
            if self.unrestricted:
                return TimeCondition(other.exclusions)
            kept = _intersect_windows(self.windows, other.exclusions)
            return TimeCondition(kept)
        # other 是受限窗口 W
        if self.unrestricted:
            # (U\\E1) \\ W = U \\ (E1 ∪ W)
            merged = _merge_windows(tuple(self.exclusions) + tuple(other.windows))
            return TimeCondition((), unrestricted=True, exclusions=merged)
        kept = self._subtract_window_sets(self.windows, other.windows)
        return TimeCondition(kept)

    @staticmethod
    def _subtract_window_sets(
        base: Sequence[TimeWindow], cuts: Sequence[TimeWindow]
    ) -> Tuple[TimeWindow, ...]:
        remaining: List[TimeWindow] = list(base)
        for cut in cuts:
            nxt: List[TimeWindow] = []
            for win in remaining:
                if cut.end <= win.start or cut.start >= win.end:
                    nxt.append(win)  # 不相交
                    continue
                if cut.start > win.start:
                    nxt.append(TimeWindow(win.start, cut.start))
                if cut.end < win.end:
                    nxt.append(TimeWindow(cut.end, win.end))
            remaining = nxt
        return tuple(remaining)

    def earliest_moment(self) -> Optional[datetime]:
        """最小见证时刻。"""
        if self.unrestricted:
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            if not any(w.start <= epoch < w.end for w in self.exclusions):
                return epoch
            # 纪元被排除：沿排序后的排除窗找第一个不被覆盖的间隙/终点
            for win in sorted(self.exclusions, key=lambda w: w.start):
                candidate = win.end
                if not any(w.start <= candidate < w.end for w in self.exclusions):
                    return candidate
            return None  # 理论上不可达（排除窗有限，时间轴无限）
        if not self.windows:
            return None
        return self.windows[0].start

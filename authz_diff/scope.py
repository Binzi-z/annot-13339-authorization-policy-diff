"""资源范围：前缀 Trie、包含/排除代数与重叠范围处理。

资源路径是 ``/`` 分隔的非空段序列（如 ``team-a/bucket/obj-7``）。
范围支持两种粒度：

- 精确匹配（EXACT）：只匹配单一资源；
- 子树前缀（SUBTREE）：匹配该前缀下的全部资源。

一个范围用 DNF（析取范式）表示为若干 ``ScopeAtom`` 的并，每个 atom 是
``include - exclude``（正向 Trie 减去排除 Trie），因此可以精确表达
重叠前缀的并/交/差，而不需要枚举任何具体资源。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

from .counters import Counters
from .errors import PolicyValidationError


class _Kind(Enum):
    EXACT = "exact"
    SUBTREE = "subtree"


def split_path(path: str) -> Tuple[str, ...]:
    if not isinstance(path, str) or not path:
        raise PolicyValidationError(f"资源路径必须是非空字符串: {path!r}")
    segments = tuple(seg for seg in path.strip("/").split("/"))
    if any(seg == "" for seg in segments):
        raise PolicyValidationError(f"资源路径含空段: {path!r}")
    return segments


class Trie:
    """正向资源 Trie：节点可标记为 EXACT 或 SUBTREE。"""

    def __init__(self):
        self.children: Dict[str, "Trie"] = {}
        self.marker: Optional[_Kind] = None

    # ---- 构造 -----------------------------------------------------------

    def add(self, segments: Sequence[str], kind: _Kind) -> None:
        node = self
        for seg in segments:
            node = node.children.setdefault(seg, Trie())
        if node.marker is not None and node.marker != kind:
            # 同一路径不能同时是精确与前缀（语义冲突的非法配置）
            raise PolicyValidationError(
                f"同一资源路径同时被声明为精确与前缀范围: {'/'.join(segments)!r}"
            )
        node.marker = kind

    def validate(self, errors: List[str], path: Tuple[str, ...] = ()) -> None:
        if self.marker is _Kind.SUBTREE and self.children:
            # 子树前缀已覆盖其全部后代，继续声明后代属于冗余/冲突配置
            errors.append(
                f"资源前缀 {'/'.join(path)!r} 已覆盖整个子树，"
                "不能再在其子树内声明重叠范围"
            )
        if self.marker is _Kind.EXACT and self.children:
            errors.append(
                f"精确资源 {'/'.join(path)!r} 下又声明了子资源范围，范围重叠冲突"
            )
        for seg, child in self.children.items():
            child.validate(errors, path + (seg,))

    @property
    def is_empty(self) -> bool:
        return self.marker is None and not self.children

    # ---- 成员判断 -------------------------------------------------------

    def contains(self, segments: Sequence[str], counters: Optional[Counters] = None) -> bool:
        node = self
        if node.marker is _Kind.SUBTREE:
            if counters is not None:
                counters.membership_checks += 1
            return True
        for seg in segments:
            child = node.children.get(seg)
            if child is None:
                if counters is not None:
                    counters.membership_checks += 1
                return False
            node = child
            if node.marker is _Kind.SUBTREE:
                if counters is not None:
                    counters.membership_checks += 1
                return True
        if counters is not None:
            counters.membership_checks += 1
        return node.marker is not None

    # ---- 标记枚举（代数运算的基础，按 Trie 节点而非资源实例展开） --------

    def markers(self, path: Tuple[str, ...] = ()):
        if self.marker is not None:
            yield path, self.marker
        for seg, child in self.children.items():
            yield from child.markers(path + (seg,))

    # ---- 代数 -----------------------------------------------------------

    @staticmethod
    def union(a: "Trie", b: "Trie") -> "Trie":
        Counters.bump_scope()
        result = Trie()
        for segments, kind in list(a.markers()) + list(b.markers()):
            existing = result._node(segments)
            # SUBTREE 覆盖 EXACT；同类型重复无害
            if existing.marker is None or kind is _Kind.SUBTREE:
                existing.marker = kind
        return Trie._canonicalize(result)

    def _node(self, segments: Sequence[str]) -> "Trie":
        node = self
        for seg in segments:
            node = node.children.setdefault(seg, Trie())
        return node

    @staticmethod
    def intersect(a: "Trie", b: "Trie") -> "Trie":
        Counters.bump_scope()
        result = Trie()
        for seg_a, kind_a in a.markers():
            for seg_b, kind_b in b.markers():
                common, kind = _intersect_marker(seg_a, kind_a, seg_b, kind_b)
                if common is not None:
                    existing = result._node(common)
                    if existing.marker is None or kind is _Kind.SUBTREE:
                        existing.marker = kind
        return Trie._canonicalize(result)

    @staticmethod
    def _canonicalize(root: "Trie") -> "Trie":
        """去除被 SUBTREE 祖先覆盖的后代标记。"""
        def prune(node: "Trie", covered: bool) -> None:
            if covered:
                node.marker = None
                node.children = {}
                return
            if node.marker is _Kind.SUBTREE:
                node.children = {}
                return
            for child in node.children.values():
                prune(child, False)
            node.children = {s: c for s, c in node.children.items() if not c.is_empty}

        prune(root, False)
        return root

    def witness_marker(self) -> Optional[Tuple[Tuple[str, ...], _Kind]]:
        """返回按字典序最小的（路径, 标记类型）。"""
        if self.marker is not None:
            return (), self.marker
        for seg in sorted(self.children):
            got = self.children[seg].witness_marker()
            if got is not None:
                return ((seg,) + got[0], got[1])
        return None

    def __eq__(self, other) -> bool:
        return isinstance(other, Trie) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def _key(self):
        return tuple(
            sorted((seg, child._key()) for seg, child in self.children.items())
        ) + ((self.marker,) if self.marker else ())


def _intersect_marker(seg_a, kind_a, seg_b, kind_b):
    """两个 Trie 标记的交集。返回 (公共段, 标记类型) 或 None。"""
    if kind_a is _Kind.SUBTREE and kind_b is _Kind.SUBTREE:
        if seg_a == seg_b[: len(seg_a)]:
            return seg_b, _Kind.SUBTREE
        if seg_b == seg_a[: len(seg_b)]:
            return seg_a, _Kind.SUBTREE
        return None, None
    if kind_a is _Kind.SUBTREE:
        if seg_b[: len(seg_a)] == seg_a:
            return seg_b, kind_b
        return None, None
    if kind_b is _Kind.SUBTREE:
        if seg_a[: len(seg_b)] == seg_b:
            return seg_a, kind_a
        return None, None
    # 两个 EXACT
    if seg_a == seg_b:
        return seg_a, _Kind.EXACT
    return None, None


@dataclass(frozen=True)
class ScopeAtom:
    """include - exclude：正向 Trie 命中且不被排除 Trie 命中。"""

    include: Trie
    exclude: Trie = field(default_factory=Trie)

    @property
    def is_empty(self) -> bool:
        if self.include.is_empty:
            return True
        # 排除 Trie 完整覆盖正向 Trie 时，atom 实际为空
        if Trie.intersect(self.include, self.exclude) == self.include:
            return True
        return False

    def contains(self, segments: Sequence[str], counters: Optional[Counters] = None) -> bool:
        return self.include.contains(segments, counters) and not self.exclude.contains(
            segments, counters
        )

    def witness(self) -> Optional[Tuple[str, ...]]:
        """生成一个确定落在本 atom 内的具体资源路径。"""
        marker = self.include.witness_marker()
        if marker is None:
            return None
        base, kind = marker
        if kind is _Kind.EXACT:
            if not self.exclude.contains(base):
                return base
            return None  # 唯一资源被排除 → atom 为空（规范化阶段通常已剔除）
        # SUBTREE：先尝试基础前缀自身；若被排除则在其下合成新段
        if not self.exclude.contains(base):
            return base
        child = base + ("__witness__",)
        suffix = 0
        while self.exclude.contains(child):
            child = base + (f"__witness{suffix}__",)
            suffix += 1
        return child


class ResourceScope:
    """资源范围 DNF：ScopeAtom 的并。"""

    def __init__(self, atoms: Sequence[ScopeAtom] = ()):
        self.atoms: Tuple[ScopeAtom, ...] = tuple(atoms)

    # ---- 工厂 -----------------------------------------------------------

    @staticmethod
    def empty() -> "ResourceScope":
        return ResourceScope(())

    @staticmethod
    def exact(path: str) -> "ResourceScope":
        trie = Trie()
        trie.add(split_path(path), _Kind.EXACT)
        return ResourceScope((ScopeAtom(trie),))

    @staticmethod
    def subtree(prefix: str) -> "ResourceScope":
        trie = Trie()
        trie.add(split_path(prefix), _Kind.SUBTREE)
        return ResourceScope((ScopeAtom(trie),))

    @staticmethod
    def from_trie(trie: Trie) -> "ResourceScope":
        return ResourceScope((ScopeAtom(trie),))

    # ---- 校验 / 成员 ----------------------------------------------------

    def validate(self) -> None:
        errors: List[str] = []
        for atom in self.atoms:
            atom.include.validate(errors)
            atom.exclude.validate(errors)
        if errors:
            raise PolicyValidationError(errors)

    @property
    def is_empty(self) -> bool:
        return all(a.is_empty for a in self.atoms)

    def contains(self, path: str, counters: Optional[Counters] = None) -> bool:
        segments = split_path(path)
        return any(a.contains(segments, counters) for a in self.atoms)

    def witness(self) -> Optional[str]:
        for atom in self.atoms:
            got = atom.witness()
            if got is not None:
                return "/".join(got)
        return None

    # ---- 代数（全部基于 Trie 标记运算，不枚举资源实例） ------------------

    def union(self, other: "ResourceScope") -> "ResourceScope":
        return ResourceScope._simplify(self.atoms + other.atoms)

    def intersection(self, other: "ResourceScope") -> "ResourceScope":
        atoms: List[ScopeAtom] = []
        for a in self.atoms:
            for b in other.atoms:
                common = Trie.intersect(a.include, b.include)
                if common.is_empty:
                    continue
                excluded = Trie.union(a.exclude, b.exclude)
                atoms.append(ScopeAtom(common, excluded))
        return ResourceScope._simplify(atoms)

    def difference(self, other: "ResourceScope") -> "ResourceScope":
        """self - other，DNF 展开规模只与范围 atom 数有关，与资源数量无关。"""
        if not other.atoms:
            return ResourceScope._simplify(self.atoms)
        atoms: List[ScopeAtom] = []
        for a in self.atoms:
            # (Ia \\ Ea) \\ (Ib \\ Eb) = (Ia \\ (Ea ∪ Ib)) ∪ (Ia ∩ Ib \\ (Ea ∪ Eb))
            for b in other.atoms:
                outside = ScopeAtom(
                    a.include, Trie.union(a.exclude, b.include)
                )
                if not outside.is_empty:
                    atoms.append(outside)
                overlap_include = Trie.intersect(a.include, b.include)
                if not overlap_include.is_empty:
                    overlap = ScopeAtom(
                        overlap_include, Trie.union(a.exclude, b.exclude)
                    )
                    if not overlap.is_empty:
                        atoms.append(overlap)
        return ResourceScope._simplify(atoms)

    @staticmethod
    def _simplify(atoms: Sequence[ScopeAtom]) -> "ResourceScope":
        seen: Dict[Tuple[Trie, Trie], ScopeAtom] = {}
        for atom in atoms:
            if atom.is_empty:
                continue
            key = (atom.include, atom.exclude)
            seen.setdefault(key, atom)
        return ResourceScope(tuple(seen.values()))

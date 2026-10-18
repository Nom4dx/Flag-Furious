from __future__ import annotations
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from threading import Lock


class BudgetExhausted(RuntimeError):
    pass


@dataclass
class ByteBudget:
    total: int
    phase_limits: dict[str, int]
    cache_size: int
    logical_bytes: int = 0
    physical_bytes: int = 0
    cached_bytes: int = 0
    requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    phase_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    exhausted_phases: set[str] = field(default_factory=set)
    _cache: OrderedDict[tuple[int, int], bytes] = field(default_factory=OrderedDict)
    _cache_bytes: int = 0
    _lock: Lock = field(default_factory=Lock)

    def read(self, handle, offset: int, size: int, phase: str, max_request: int) -> bytes:
        size = min(size, max_request)
        if size <= 0:
            return b""
        key = (offset, size)
        with self._lock:
            self.requests += 1
            self.logical_bytes += size
            if key in self._cache:
                self.cache_hits += 1
                data = self._cache.pop(key)
                self._cache[key] = data
                self.cached_bytes += len(data)
                return data
            self.cache_misses += 1
            remaining = self.total - self.physical_bytes
            phase_remaining = self.phase_limits.get(phase, self.total) - self.phase_bytes[phase]
            allowed = min(size, remaining, phase_remaining)
            if allowed <= 0:
                self.exhausted_phases.add(phase)
                raise BudgetExhausted(f"byte budget exhausted during {phase}")
            handle.seek(offset)
            data = handle.read(allowed)
            self.physical_bytes += len(data)
            self.phase_bytes[phase] += len(data)
            if self.cache_size and data:
                self._cache[key] = data
                self._cache_bytes += len(data)
                while self._cache_bytes > self.cache_size and self._cache:
                    _, evicted = self._cache.popitem(last=False)
                    self._cache_bytes -= len(evicted)
            return data

    def stats(self) -> dict[str, int | dict[str, int]]:
        return {
            "logical_bytes": self.logical_bytes, "physical_bytes": self.physical_bytes,
            "cached_bytes": self.cached_bytes, "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses, "requests": self.requests,
            "remaining": max(0, self.total - self.physical_bytes), "by_phase": dict(self.phase_bytes),
            "exhausted_phases": sorted(self.exhausted_phases),
        }

    def can_external(self, size: int, phase: str) -> bool:
        return size <= self.total - self.physical_bytes and size <= self.phase_limits.get(phase, self.total) - self.phase_bytes[phase]

    def account_external(self, size: int, phase: str) -> None:
        if not self.can_external(size, phase):
            self.exhausted_phases.add(phase); raise BudgetExhausted(f"byte budget exhausted during external {phase}")
        self.requests += 1; self.logical_bytes += size; self.physical_bytes += size; self.phase_bytes[phase] += size

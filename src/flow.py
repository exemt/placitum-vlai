from __future__ import annotations

import math
import time
from typing import Any

WINDOW = 10
BUCKETS = 24


class Counter:
    def __init__(self) -> None:
        self._ops = [0] * WINDOW
        self._errs = [0] * WINDOW
        self._hist: list[list[int]] = [[0] * BUCKETS for _ in range(WINDOW)]
        self._max_ms = [0.0] * WINDOW
        self._sum_ms = [0.0] * WINDOW
        self._epoch = 0

    def add(self, is_err: bool, latency_ms: float) -> None:
        self.add_n(1, is_err, latency_ms)

    def add_n(self, n: int, is_err: bool, latency_ms: float) -> None:
        if n <= 0:
            return
        now = int(time.time())
        self._advance(now)
        slot = now % WINDOW
        self._ops[slot] += n
        if is_err:
            self._errs[slot] += n
        ms = latency_ms if latency_ms > 0 else 0.0
        self._hist[slot][_bucket_of(ms)] += n
        self._sum_ms[slot] += ms * n
        if ms > self._max_ms[slot]:
            self._max_ms[slot] = ms

    def snapshot(self) -> dict[str, Any]:
        now = int(time.time())
        self._advance(now)

        ops = sum(self._ops)
        errs = sum(self._errs)
        max_ms = max(self._max_ms)
        sum_ms = sum(self._sum_ms)
        hist = [0] * BUCKETS
        for row in self._hist:
            for b in range(BUCKETS):
                hist[b] += row[b]

        out: dict[str, Any] = {"ops": _round1(ops / WINDOW)}
        if errs:
            out["err"] = _round1(errs / WINDOW)
        if ops:
            out["p50_ms"] = _percentile(hist, ops, 0.5)
            out["p95_ms"] = _percentile(hist, ops, 0.95)
            out["max_ms"] = _round1(max_ms)
            out["avg_ms"] = _round1(sum_ms / ops)
        return out

    def _advance(self, now: int) -> None:
        if self._epoch == 0:
            self._epoch = now
            return
        if now <= self._epoch:
            return
        dt = now - self._epoch
        if dt >= WINDOW:
            for slot in range(WINDOW):
                self._clear(slot)
        else:
            for i in range(1, dt + 1):
                self._clear((self._epoch + i) % WINDOW)
        self._epoch = now

    def _clear(self, slot: int) -> None:
        self._ops[slot] = 0
        self._errs[slot] = 0
        self._max_ms[slot] = 0.0
        self._sum_ms[slot] = 0.0
        for b in range(BUCKETS):
            self._hist[slot][b] = 0


def _bucket_of(ms: float) -> int:
    if ms < 1:
        return 0
    b = int(math.log2(ms)) + 1
    return min(b, BUCKETS - 1)


def _bucket_mid(b: int) -> float:
    if b == 0:
        return 0.5
    lo = 2.0 ** (b - 1)
    hi = 2.0 ** b
    return (lo + hi) / 2


def _percentile(hist: list[int], total: int, frac: float) -> float:
    if total == 0:
        return 0.0
    target = max(1, math.ceil(frac * total))
    acc = 0
    for b, count in enumerate(hist):
        acc += count
        if acc >= target:
            return _round1(_bucket_mid(b))
    return _round1(_bucket_mid(BUCKETS - 1))


def _round1(v: float) -> float:
    return round(v, 1)

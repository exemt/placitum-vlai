from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass
class _Slot(Generic[T]):
    item: T
    deadline: float


class Gate(Generic[T]):
    def __init__(self, maxsize: int, full: str, min_budget_s: float = 0.0) -> None:
        self.maxsize = max(1, maxsize)
        self.full = full
        self.min_budget_s = min_budget_s
        self.items: deque[_Slot[T]] = deque()
        self.cond = asyncio.Condition()
        self.shed = 0
        self.expired = 0
        self._unfinished = 0
        self._idle = asyncio.Event()
        self._idle.set()

    def queued(self) -> int:
        return len(self.items)

    def _take_stale(self, now: float) -> list[T]:
        stale: list[T] = []
        kept: deque[_Slot[T]] = deque()
        for slot in self.items:
            if slot.deadline - now < self.min_budget_s:
                stale.append(slot.item)
                self.expired += 1
                self._unfinished -= 1
            else:
                kept.append(slot)
        self.items = kept
        if self._unfinished <= 0:
            self._unfinished = 0
            self._idle.set()
        return stale

    async def submit(
        self, item: T, wait_s: float, full: str | None = None
    ) -> tuple[str, list[T]]:
        now = time.monotonic()
        deadline = now + max(wait_s, 0.0)
        evicted: list[T] = []

        if deadline - now < self.min_budget_s:
            self.expired += 1
            return "deadline", evicted

        async with self.cond:
            evicted.extend(self._take_stale(time.monotonic()))
            if len(self.items) < self.maxsize:
                self._put(item, deadline)
                return "", evicted

            if (full or self.full) != "wait":
                self.shed += 1
                return "limit", evicted

            left = deadline - time.monotonic()
            if left < self.min_budget_s:
                self.expired += 1
                return "deadline", evicted

            try:
                await asyncio.wait_for(self._wait_slot(deadline, evicted), timeout=max(left, 0.0))
            except asyncio.TimeoutError:
                evicted.extend(self._take_stale(time.monotonic()))
                self.expired += 1
                return "deadline", evicted

            evicted.extend(self._take_stale(time.monotonic()))
            if len(self.items) < self.maxsize:
                self._put(item, deadline)
                return "", evicted

            self.expired += 1
            return "deadline", evicted

    def _put(self, item: T, deadline: float) -> None:
        self.items.append(_Slot(item, deadline))
        self._unfinished += 1
        self._idle.clear()
        self.cond.notify_all()

    async def _wait_slot(self, deadline: float, evicted: list[T]) -> None:
        while len(self.items) >= self.maxsize:
            evicted.extend(self._take_stale(time.monotonic()))
            if len(self.items) < self.maxsize:
                return
            if deadline - time.monotonic() < self.min_budget_s:
                raise asyncio.TimeoutError
            await self.cond.wait()

    async def take(self) -> tuple[T | None, list[T]]:
        async with self.cond:
            while True:
                stale = self._take_stale(time.monotonic())
                if self.items:
                    slot = self.items.popleft()
                    self.cond.notify_all()
                    return slot.item, stale
                if stale:
                    return None, stale
                await self.cond.wait()

    async def sweep(self) -> list[T]:
        async with self.cond:
            stale = self._take_stale(time.monotonic())
            if stale:
                self.cond.notify_all()
            return stale

    def done(self) -> None:
        self._unfinished -= 1
        if self._unfinished <= 0:
            self._unfinished = 0
            self._idle.set()

    async def join(self) -> None:
        await self._idle.wait()

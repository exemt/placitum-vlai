from __future__ import annotations

import asyncio
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any

STREAM = "WAF_LOG"
KIND = "log"
VERSION = 1

MAX_TEXT = 8 * 1024

MAX_LINES = 500
MAX_SIZE = 256 * 1024
FLUSH_EVERY = 0.2
MAX_PENDING = 20000

MAX_AGE_S = 24 * 3600
STREAM_BYTES = 128 * 1024 * 1024

_BAD = str.maketrans({">": "_", "*": "_", " ": "_", "\t": "_"})


def subject(writer: str) -> str:
    return "waf.log." + (writer or "unknown").translate(_BAD)


class LogSink:
    def __init__(self, writer: str, service: str, io: Any = None) -> None:
        self._writer = writer or "unknown"
        self._service = service or "unknown"
        self._io = io
        self._lock = threading.Lock()
        self._pending: list[dict[str, Any]] = []
        self._size = 0
        self._dropped = 0
        self._failed = 0
        self._nc: Any = None

    @property
    def writer(self) -> str:
        return self._writer

    def attach(self, nc: Any) -> None:
        self._nc = nc

    def add(self, severity: str, text: str) -> None:
        if not text:
            return
        if len(text) > MAX_TEXT:
            text = text[:MAX_TEXT]
        line = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "service": self._service,
            "severity": severity or "",
            "text": text,
        }
        cut = 0
        with self._lock:
            self._pending.append(line)
            self._size += len(text) + 64
            if len(self._pending) > MAX_PENDING:
                cut = len(self._pending) - MAX_PENDING
                self._dropped += cut
                del self._pending[:cut]
        if cut and self._io is not None:
            self._io.add_n(cut, True, 0.0)

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def failed(self) -> int:
        with self._lock:
            return self._failed

    async def run(self) -> None:
        try:
            while True:
                await asyncio.sleep(FLUSH_EVERY)
                await self.flush()
        except asyncio.CancelledError:
            await self.flush()
            raise

    async def flush(self) -> None:
        nc = self._nc
        if nc is None:
            return
        while True:
            lines = self._take()
            if not lines:
                return
            await self._publish(nc, lines)

    def _take(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self._pending:
                return []
            lines = self._pending[:MAX_LINES]
            del self._pending[:MAX_LINES]
            self._size = sum(len(l["text"]) + 64 for l in self._pending)
            return lines

    async def _publish(self, nc: Any, lines: list[dict[str, Any]]) -> None:
        started = time.perf_counter()
        body = json.dumps(
            {"v": VERSION, "kind": KIND, "writer": self._writer, "lines": lines},
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        err = False
        try:
            await nc.publish(subject(self._writer), body)
        except Exception:  # noqa: BLE001
            err = True
            with self._lock:
                self._failed += len(lines)
        if self._io is not None:
            self._io.add_n(len(lines), err, (time.perf_counter() - started) * 1000.0)


async def ensure(nc: Any) -> None:
    js = nc.jetstream()
    await js.add_stream(
        name=STREAM,
        subjects=["waf.log.>"],
        storage="file",
        retention="limits",
        max_age=MAX_AGE_S,
        max_bytes=STREAM_BYTES,
        discard="old",
    )

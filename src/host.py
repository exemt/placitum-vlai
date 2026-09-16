from __future__ import annotations

import os
from typing import Any

_prev_idle = 0
_prev_total = 0


def collect() -> dict[str, Any]:
    global _prev_idle, _prev_total

    load1, load5, load15 = _read_load()
    idle, total = _cpu_ticks()
    usage = 0.0
    if _prev_total:
        idle_d = idle - _prev_idle
        total_d = total - _prev_total
        if total_d > 0:
            usage = max(0.0, 1.0 - idle_d / total_d)
    _prev_idle, _prev_total = idle, total

    mem_total, mem_available = _read_mem()
    mem_used = mem_total - mem_available if mem_total > mem_available else 0

    return {
        "cpu": {
            "cores": os.cpu_count() or 0,
            "usage": round(usage, 4),
            "load1": load1,
            "load5": load5,
            "load15": load15,
        },
        "memory": {
            "total": mem_total,
            "used": mem_used,
            "available": mem_available,
        },
        "uptime_s": _read_uptime(),
    }


def _read_uptime() -> int:
    fields = _fields_of("/proc/uptime")
    if not fields:
        return 0
    try:
        return int(float(fields[0]))
    except ValueError:
        return 0


def _read_load() -> tuple[float, float, float]:
    try:
        load1, load5, load15 = os.getloadavg()
        return load1, load5, load15
    except (OSError, AttributeError):
        return 0.0, 0.0, 0.0


def _cpu_ticks() -> tuple[int, int]:
    try:
        with open("/proc/stat", "r", encoding="ascii") as fh:
            line = fh.readline()
    except OSError:
        return 0, 0
    fields = line.split()
    if len(fields) < 5 or fields[0] != "cpu":
        return 0, 0
    try:
        nums = [int(f) for f in fields[1:]]
    except ValueError:
        return 0, 0
    return nums[3], sum(nums)


def _read_mem() -> tuple[int, int]:
    total = 0
    available = 0
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if not parts:
                    continue
                try:
                    value = int(parts[0]) * 1024
                except ValueError:
                    continue
                if key == "MemTotal":
                    total = value
                elif key == "MemAvailable":
                    available = value
    except OSError:
        pass
    return total, available


def _fields_of(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="ascii") as fh:
            return fh.read().split()
    except OSError:
        return []

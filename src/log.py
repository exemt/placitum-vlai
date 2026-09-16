from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

LEVELS = ("debug", "info", "notice", "warn", "error", "crit", "alert")
_ORDER = {name: index for index, name in enumerate(LEVELS)}
_threshold = _ORDER["info"]

_sink = None


def attach(sink: object) -> None:
    global _sink
    _sink = sink


def set_level(level: str) -> bool:
    global _threshold
    if level not in _ORDER:
        return False
    _threshold = _ORDER[level]
    return True


def current_level() -> str:
    return LEVELS[_threshold]


def log(level: str, msg: str, **fields: object) -> None:
    if _ORDER.get(level, 1) < _threshold:
        return
    line = json.dumps(
        {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
         "level": level, "msg": msg, **fields},
        ensure_ascii=False,
        default=str,
    )
    stream = sys.stderr if _ORDER.get(level, 1) >= _ORDER["warn"] else sys.stdout
    stream.write(line + "\n")
    stream.flush()
    if _sink is not None:
        _sink.add(level, line)

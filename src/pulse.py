from __future__ import annotations

import socket
import uuid
from datetime import datetime, timezone
from typing import Any


def new_inspector_id() -> str:
    return str(uuid.uuid4())


def status_subject(name: str, inspector_id: str) -> str:
    return "WAF_STATUS.inspector.%s.%s" % (_token(name), _token(inspector_id))


def build_pulse(
    *,
    inspector_id: str,
    name: str,
    subject: str,
    queue: str,
    device: str,
    host: dict[str, Any],
    accepted: int,
    queued: int = 0,
    queue_depth: int = 8,
    workers: int = 1,
    io: dict[str, dict[str, Any]] | None = None,
    window_s: int | None = None,
    config_hash: str = "",
    rev: int = 0,
    apply: str = "",
    profiles: list[str] | None = None,
) -> dict[str, Any]:
    pulse: dict[str, Any] = {
        "v": 1,
        "kind": "inspector",
        "id": inspector_id,
        "name": name,
        "subject": subject,
        "queue": queue,
        "hostname": socket.gethostname(),
        "ready": True,
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "host": host,
        "work": {
            "device": device,
            "workers": workers,
            "queue_depth": queue_depth,
            "queued": queued,
            "accepted": accepted,
        },
    }
    if io:
        pulse["io"] = io
        if window_s is not None:
            pulse["window_s"] = window_s
    if config_hash:
        pulse["config_hash"] = config_hash
        if rev:
            pulse["rev"] = rev
    if apply:
        pulse["apply"] = apply
    if profiles:
        pulse["profiles"] = profiles
    return pulse


def _token(value: str) -> str:
    return value.replace(">", "_").replace(".", "_").replace(" ", "_").replace("*", "_")

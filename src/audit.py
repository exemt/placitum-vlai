from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

VERSION = 1

SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_OF = {
    "Low": SEVERITY_LOW,
    "Medium": SEVERITY_MEDIUM,
    "High": SEVERITY_HIGH,
    "Critical": SEVERITY_CRITICAL,
}


def finding(
    code: str,
    severity: str,
    target: str,
    *,
    confidence: float | None = None,
    evidence: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "severity": severity, "target": target}
    if confidence is not None:
        out["confidence"] = round(float(confidence), 4)
    if evidence:
        out["evidence"] = evidence[:256]
    return out


def build(
    request: dict[str, Any] | None,
    reply: dict[str, Any] | None,
    *,
    findings: list[dict[str, Any]] | None = None,
    engine: dict[str, Any] | None = None,
    engine_ms: float = 0.0,
) -> dict[str, Any]:
    request = request or {}
    reply = reply or {}
    route = request.get("route") or {}

    event: dict[str, Any] = {
        "v": VERSION,
        "kind": "inspector",
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "ray": request.get("ray") or "",
        "node": request.get("node") or "",
        "phase": request.get("phase") or "request",
        "inspector": reply.get("inspector") or request.get("inspector") or "",
        "profile": route.get("profile") or "default",
        "verdict": reply.get("verdict") or "",
        "engine_ms": round(float(engine_ms), 3),
        "findings": findings or [],
    }

    if reply.get("verdict") == "score" and reply.get("score") is not None:
        event["score"] = reply["score"]

    if engine:
        event["engine"] = engine

    return event

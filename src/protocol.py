from __future__ import annotations

import json
import re
from typing import Any

PROTOCOL_VERSION = 2
PHASES = frozenset({"request", "response", "frame"})
VERDICTS = frozenset({"allow", "score", "redirect", "deny", "error"})

OBJECTS = ("headers", "args", "body")

_RID_RE = re.compile(r'"rid"\s*:\s*"([0-9a-fA-F]{1,32})"')


def sniff_rid(payload: str) -> str:
    match = _RID_RE.search(payload)
    return match.group(1) if match else ""


def parse_request(payload: str) -> tuple[dict[str, Any] | None, str, str]:
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        return None, sniff_rid(payload), "invalid json: %s" % exc

    if not isinstance(raw, dict):
        return None, "", "message is not an object"

    rid = raw.get("rid") if isinstance(raw.get("rid"), str) else ""
    if not isinstance(raw.get("v"), (int, float)):
        return None, rid, "field v is missing or not a number"
    if rid == "":
        return None, "", "field rid is missing or empty"
    if not isinstance(raw.get("inspector"), str) or raw["inspector"] == "":
        return None, rid, "field inspector is missing or empty"
    if raw.get("phase") not in PHASES:
        return None, rid, "field phase is invalid: %s" % raw.get("phase")
    if not isinstance(raw.get("deadline_ms"), (int, float)):
        return None, rid, "field deadline_ms is missing or not a number"

    conn = raw.get("conn")
    if not isinstance(conn, dict) or not isinstance(conn.get("client_ip"), str):
        return None, rid, "section conn is missing or has no client_ip"

    http = raw.get("http")
    if not isinstance(http, dict):
        return None, rid, "section http is missing"
    if not isinstance(http.get("method"), str) or not isinstance(http.get("uri"), str):
        return None, rid, "section http has no method or uri"

    store = raw.get("store")
    if store is None:
        raw["store"] = store = {}
    elif not isinstance(store, dict):
        return None, rid, "section store is neither object nor null"

    for name in OBJECTS:
        locator = store.get(name)
        if locator is not None and not isinstance(locator, dict):
            return None, rid, "field store.%s is neither object nor null" % name

    raw["v"] = int(raw["v"])
    raw["deadline_ms"] = int(raw["deadline_ms"])
    return raw, rid, ""


def locator(request: dict[str, Any], name: str) -> dict[str, Any] | None:
    store = request.get("store")
    if not isinstance(store, dict):
        return None
    found = store.get(name)
    return found if isinstance(found, dict) else None


def needed(request: dict[str, Any], name: str) -> bool:
    needs = request.get("needs")
    return isinstance(needs, list) and name in needs


def audit_subject(request: dict[str, Any]) -> str:
    subject = request.get("audit_subject")
    return subject if isinstance(subject, str) and subject else ""


def reply(
    request: dict[str, Any],
    inspector: str,
    verdict: str,
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "v": int(request.get("v") or PROTOCOL_VERSION),
        "rid": str(request.get("rid") or ""),
        "inspector": inspector,
        "verdict": verdict,
    }
    out.update({key: value for key, value in extra.items() if value is not None})
    return out

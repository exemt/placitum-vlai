from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, unquote_plus

from protocol import locator
from store import fetch

JSON_KEYS = ("description", "text", "advisory", "details", "описание")
MAX_CHARS = 3072
MIN_CHARS = 4


def extract(request: dict[str, Any]) -> dict[str, Any]:
    body = locator(request, "body")

    if body is None:
        return _args_or(request, {"text": "", "source": "absent", "body": "absent"})

    if body.get("unavailable"):
        state = "unavailable:%s" % body["unavailable"]

        return _args_or(request, {"text": "", "source": "unavailable", "body": state})

    raw, why = fetch(body)

    if why:
        return {
            "text": "",
            "source": "unavailable",
            "body": "unavailable:" + why,
            "unavailable": why,
        }

    if raw:
        parsed = _from_json(raw)
        if parsed is not None:
            parsed["body"] = "store"
            return parsed
        text = _as_text(raw)
        if text:
            return {"text": _clip(text), "source": "body.store", "body": "store"}

    return _args_or(request, {"text": "", "source": "external", "body": "external"})


def _args_or(request: dict[str, Any], empty: dict[str, Any]) -> dict[str, Any]:
    from_args, why = _from_args(request)

    if why:
        return {
            "text": "",
            "source": "unavailable",
            "body": empty["body"],
            "unavailable": why,
        }

    if from_args is not None:
        from_args["body"] = empty["body"]

        return from_args

    return empty


def _from_json(raw: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    for key in JSON_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return {
                "text": _clip(value.strip()),
                "source": "body.json.%s" % key,
            }
    return None


def _from_args(request: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    raw, why = fetch(locator(request, "args"))
    if why:
        return None, why
    if not raw:
        return None, ""
    try:
        args = raw.decode("utf-8")
    except UnicodeDecodeError:
        args = raw.decode("utf-8", errors="replace")
    if not args:
        return None, ""
    parsed = parse_qs(args, keep_blank_values=True)
    for key in JSON_KEYS:
        values = parsed.get(key)
        if values and values[0].strip():
            return {
                "text": _clip(unquote_plus(values[0]).strip()),
                "source": "args.%s" % key,
            }, ""
    return None, ""


def _as_text(raw: bytes) -> str:
    if not raw:
        return ""
    if b"\x00" in raw[:256]:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    return text.strip()


def _clip(text: str) -> str:
    if len(text) <= MAX_CHARS:
        return text
    return text[:MAX_CHARS]

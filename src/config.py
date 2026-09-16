from __future__ import annotations

import os
import socket

from conf import find_conf, load_conf


def _split(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _ms(raw: str | None, fallback: int) -> int:
    if raw is None or raw.strip() == "":
        return fallback
    text = raw.strip()
    if text.isdigit():
        return int(text)
    if text.endswith("ms") and text[:-2].replace(".", "", 1).isdigit():
        return int(float(text[:-2]))
    if text.endswith("s") and text[:-1].replace(".", "", 1).isdigit():
        return int(float(text[:-1]) * 1000)
    return fallback


def _log_ship(src: dict[str, str]) -> bool:
    return (src.get("WAF_LOG_SHIP") or "").strip().lower() not in ("off", "0", "no", "false")


def _log_writer(src: dict[str, str], fallback: str) -> str:
    name = (src.get("WAF_LOG_WRITER") or "").strip()
    if name:
        return name
    return socket.gethostname() or fallback


def _prior_rules(raw: str | None) -> list[str]:
    senders: list[str] = []
    if not raw or not raw.strip():
        return senders
    for part in raw.split(","):
        name = part.strip()
        if not name:
            continue
        if name == "*" or ":" in name:
            raise ValueError("WAF_VLAI_PRIOR entry %r is not a sender name" % name)
        if name not in senders:
            senders.append(name)
    return senders


def load(env: dict[str, str] | None = None) -> dict:
    src = env if env is not None else os.environ
    name = src.get("WAF_VLAI_NAME", "vlai")
    queue_max = 256
    queue_full = "drop"
    queue_expand = "off"
    redis_url = ""
    conf_path = find_conf(src.get("WAF_VLAI_CONF") or None)
    if conf_path:
        parsed = load_conf(conf_path)
        queue_max = parsed.get("queue_max", queue_max)
        queue_full = parsed.get("queue_full", queue_full)
        queue_expand = parsed.get("queue_expand", queue_expand)
        redis_url = parsed.get("redis_url", redis_url)
    if src.get("REDIS_URL"):
        redis_url = src["REDIS_URL"].strip()
    if src.get("WAF_VLAI_QUEUE_DEPTH"):
        queue_max = max(1, int(src["WAF_VLAI_QUEUE_DEPTH"]))
    if src.get("WAF_VLAI_QUEUE_FULL"):
        queue_full = src["WAF_VLAI_QUEUE_FULL"].strip()
    if src.get("WAF_VLAI_QUEUE_EXPAND"):
        queue_expand = src["WAF_VLAI_QUEUE_EXPAND"].strip()
    if queue_full not in ("drop", "wait"):
        raise ValueError("queue_full must be drop or wait, got %r" % queue_full)
    if queue_expand not in ("off", "ask"):
        raise ValueError("queue_expand must be off or ask, got %r" % queue_expand)
    return {
        "servers": _split(src.get("NATS_URL", "nats://127.0.0.1:4222")),
        "subject": src.get("WAF_VLAI_SUBJECT", "waf.req.vlai"),
        "queue": src.get("WAF_VLAI_QUEUE", name),
        "name": name,
        "user": src.get("NATS_USER") or None,
        "pass": src.get("NATS_PASS") or None,
        "token": src.get("NATS_TOKEN") or None,
        "versions": [int(part) for part in _split(src.get("WAF_VLAI_VERSIONS", "2"))],
        "log_level": src.get("WAF_VLAI_LOG", "info"),
        "log_ship": _log_ship(src),
        "log_writer": _log_writer(src, name),
        "heartbeat_every_ms": _ms(src.get("WAF_HEARTBEAT_EVERY"), 4000),
        "min_budget_ms": int(src.get("VLAI_MIN_BUDGET_MS", "8")),
        "prior_rules": _prior_rules(src.get("WAF_VLAI_PRIOR")),
        "model": src.get("VLAI_MODEL", "CIRCL/vulnerability-severity-classification-russian-ruRoberta-large"),
        "device": src.get("VLAI_DEVICE", "cpu"),
        "queue_depth": queue_max,
        "queue_full": queue_full,
        "queue_expand": queue_expand,
        "conf_path": conf_path,
        "redis_url": redis_url,
        "geo_url": (src.get("WAF_VLAI_GEO_URL") or "").strip(),
        "geo_timeout_ms": _ms(src.get("WAF_VLAI_GEO_TIMEOUT"), 500),
    }

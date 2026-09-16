from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

QUEUE_FULL = frozenset({"drop", "wait"})
QUEUE_EXPAND = frozenset({"off", "ask"})


class ConfError(ValueError):
    pass


def parse_conf(text: str, *, name: str = "inspector.conf") -> dict:
    out: dict = {}
    seen: set[str] = set()
    block = ""
    opened = 0

    for i, raw in enumerate(text.splitlines(), 1):
        line = _text(raw)
        if line == "":
            continue

        if block:
            if line == "}":
                block = ""
                continue
            _redis_key(out, seen, line, name, i)
            continue

        if line == "}":
            raise ConfError("%s:%d: unexpected }" % (name, i))

        if line.endswith("{"):
            head = line[:-1].strip()
            if head != "redis":
                raise ConfError("%s:%d: unknown block %r" % (name, i, head))
            if head in seen:
                raise ConfError("%s:%d: %s block is set twice" % (name, i, head))
            seen.add(head)
            block, opened = head, i
            continue

        key, value = _directive(line, name, i)
        if key in seen:
            raise ConfError("%s:%d: %s is set twice" % (name, i, key))
        seen.add(key)

        if key == "queue_max":
            if not value.isdigit() or int(value) < 1:
                raise ConfError("%s:%d: queue_max must be a positive integer, got %r" % (name, i, value))
            out["queue_max"] = int(value)
        elif key == "queue_full":
            if value not in QUEUE_FULL:
                raise ConfError("%s:%d: queue_full must be drop or wait, got %r" % (name, i, value))
            out["queue_full"] = value
        elif key == "queue_expand":
            if value not in QUEUE_EXPAND:
                raise ConfError("%s:%d: queue_expand must be off or ask, got %r" % (name, i, value))
            out["queue_expand"] = value
        else:
            raise ConfError("%s:%d: unknown directive %r" % (name, i, key))

    if block:
        raise ConfError("%s:%d: %s block is not closed" % (name, opened, block))

    return out


def _redis_key(out: dict, seen: set[str], line: str, name: str, i: int) -> None:
    key, value = _directive(line, name, i)
    ident = "redis." + key
    if ident in seen:
        raise ConfError("%s:%d: redis %s is set twice" % (name, i, key))
    seen.add(ident)

    if key == "internal":
        raise ConfError("%s:%d: redis internal: vlai keeps no state in Redis, remove the key" % (name, i))
    if key != "url":
        raise ConfError("%s:%d: unknown key %r in the redis block, want url" % (name, i, key))

    parsed = urlparse(value)
    if parsed.scheme not in ("redis", "rediss") or not parsed.hostname:
        raise ConfError(
            "%s:%d: redis url must be redis://host:port[/db] or rediss://..., got %r" % (name, i, value)
        )
    out["redis_url"] = value


def _directive(line: str, name: str, i: int) -> tuple[str, str]:
    if not line.endswith(";"):
        raise ConfError("%s:%d: missing semicolon" % (name, i))
    key, _, rest = line[:-1].strip().partition(" ")
    value = rest.strip()
    if not key or not value or any(ch.isspace() for ch in value):
        raise ConfError("%s:%d: directive expects one value" % (name, i))
    return key, value


def load_conf(path: str) -> dict:
    return parse_conf(Path(path).read_text(encoding="utf-8"), name=path)


def _text(line: str) -> str:
    if "#" in line:
        line = line[: line.index("#")]
    return line.strip()


def find_conf(explicit: str | None) -> str:
    if explicit:
        return explicit
    for candidate in ("inspector.conf", "/app/inspector.conf"):
        if Path(candidate).is_file():
            return candidate
    return ""

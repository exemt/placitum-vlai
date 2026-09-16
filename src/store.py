from __future__ import annotations

import os
import socket
from typing import Any
from urllib.parse import urlparse

UNAVAILABLE_NO_STORE = "store_unconfigured"
UNAVAILABLE_STORE_ERROR = "store_error"
UNAVAILABLE_UNKNOWN_DRIVER = "unknown_driver"

_default_url = ""


def configure(url: str | None) -> None:
    global _default_url
    _default_url = url or ""


def fetch(
    locator: dict[str, Any] | None, redis_url: str | None = None
) -> tuple[bytes | None, str]:
    if not isinstance(locator, dict):
        return None, ""

    if locator.get("unavailable"):
        return None, ""

    key = locator.get("key")
    driver = locator.get("driver") or ""

    if not isinstance(key, str) or not key:
        return None, ""

    if driver != "redis":
        return None, UNAVAILABLE_UNKNOWN_DRIVER

    url = redis_url or _default_url or os.environ.get("REDIS_URL") or ""
    if not url:
        return None, UNAVAILABLE_NO_STORE

    raw = redis_get(url, key)
    if raw is None:
        return None, UNAVAILABLE_STORE_ERROR

    return raw, ""


def redis_get(url: str, key: str, timeout: float = 0.05) -> bytes | None:
    if not url:
        return None

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 6379
    cmd = _resp_array(["GET", key])

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(cmd)
            return _read_bulk(sock)
    except OSError:
        return None


def redis_set(url: str, key: str, value: bytes, ttl_s: int, timeout: float = 0.2) -> bool:
    if not url:
        return False

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 6379
    cmd = _resp_array(["SET", key, value, "EX", str(ttl_s)])

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(cmd)
            return sock.recv(64).startswith(b"+OK")
    except OSError:
        return False


def _resp_array(parts: list[str | bytes]) -> bytes:
    out = [f"*{len(parts)}\r\n".encode()]

    for part in parts:
        raw = part if isinstance(part, bytes) else part.encode("utf-8")
        out.append(f"${len(raw)}\r\n".encode())
        out.append(raw)
        out.append(b"\r\n")

    return b"".join(out)


def _read_bulk(sock: socket.socket) -> bytes | None:
    buf = b""

    while b"\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk

    line, rest = buf.split(b"\r\n", 1)

    if not line.startswith(b"$"):
        return None

    try:
        n = int(line[1:])
    except ValueError:
        return None

    if n < 0:
        return None

    while len(rest) < n + 2:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        rest += chunk

    return rest[:n]

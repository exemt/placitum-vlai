from __future__ import annotations

import asyncio
import bisect
import ipaddress
import json
import time
import urllib.parse
import urllib.request
from typing import Any, Callable

WRITE_ADDR = "addr"
WRITE_NET = "net"
WRITE_NET_ALL = "net_all"
WRITE_ASN = "asn"

NEG_TTL_S = 600.0
NEG_MAX = 100_000


class GeoUnavailable(Exception):
    pass


def networked(write: str) -> bool:
    return write in (WRITE_NET, WRITE_NET_ALL, WRITE_ASN)


def values(asns: list[dict[str, Any]], write: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    def add(prefix: object) -> None:
        text = str(prefix or "")
        if text and text not in seen:
            seen.add(text)
            out.append(text)

    for row in asns:
        if write == WRITE_NET_ALL:
            add(row.get("prefix"))
        elif write == WRITE_NET and row.get("effective"):
            add(row.get("prefix"))
        elif write == WRITE_ASN and row.get("effective"):
            for prefix in row.get("prefixes") or []:
                add(prefix)
    return out


Fetch = Callable[[str, bool, float], Any]


def _http_fetch(base: str) -> Fetch:
    def fetch(addr: str, expand: bool, timeout: float) -> Any:
        query = {"addr": addr}
        if expand:
            query["expand"] = "asn"
        url = "%s/lookup?%s" % (base.rstrip("/"), urllib.parse.urlencode(query))
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    return fetch


def _unmap(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


class Geo:
    def __init__(self, url: str, timeout_s: float = 0.5, fetch: Fetch | None = None) -> None:
        self.timeout_s = timeout_s
        self._fetch = fetch or _http_fetch(url)
        self.gen = 0
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._spans: dict[int, list[tuple[int, int, list[dict[str, Any]]]]] = {4: [], 6: []}
        self._comps: dict[int, list[str]] = {}
        self._neg: dict[str, float] = {}

    async def write(self, write: str, addr: str) -> list[str]:
        try:
            ip = _unmap(ipaddress.ip_address(addr))
        except ValueError:
            return []
        return values(await self._lookup(ip, write == WRITE_ASN), write)

    def _cached(self, ip, expand: bool) -> list[dict[str, Any]] | None:
        starts = self._starts[ip.version]
        i = bisect.bisect_right(starts, int(ip)) - 1
        if i < 0:
            return None
        lo, hi, rows = self._spans[ip.version][i]
        if int(ip) > hi:
            return None
        if not expand:
            return rows
        out = []
        for row in rows:
            comp = self._comps.get(int(row.get("asn") or 0))
            if comp is None:
                return None
            out.append({**row, "prefixes": comp})
        return out

    def _insert(self, version: int, lo: int, hi: int, rows: list[dict[str, Any]]) -> None:
        starts = self._starts[version]
        spans = self._spans[version]
        i = bisect.bisect_left(starts, lo)
        if i < len(spans) and spans[i][0] <= hi:
            return
        if i > 0 and lo <= spans[i - 1][1]:
            return
        starts.insert(i, lo)
        spans.insert(i, (lo, hi, rows))

    def _reset(self, gen: int) -> None:
        self.gen = gen
        self._starts = {4: [], 6: []}
        self._spans = {4: [], 6: []}
        self._comps = {}
        self._neg = {}

    def _remember(self, key: str) -> None:
        now = time.monotonic()
        if len(self._neg) >= NEG_MAX:
            for addr in [addr for addr, until in self._neg.items() if until <= now]:
                del self._neg[addr]
            keep = int(NEG_MAX * 0.9)
            for addr in list(self._neg)[: max(0, len(self._neg) - keep)]:
                del self._neg[addr]
        self._neg[key] = now + NEG_TTL_S

    async def _lookup(self, ip, expand: bool) -> list[dict[str, Any]]:
        cached = self._cached(ip, expand)
        if cached is not None:
            return cached
        until = self._neg.get(str(ip))
        if until is not None and until > time.monotonic():
            return []
        try:
            reply = await asyncio.wait_for(
                asyncio.to_thread(self._fetch, str(ip), expand, self.timeout_s),
                timeout=self.timeout_s + 0.05,
            )
        except Exception as exc:  # noqa: BLE001
            raise GeoUnavailable(str(exc) or type(exc).__name__) from exc
        if not isinstance(reply, dict):
            raise GeoUnavailable("reply is not an object")
        gen = int(reply.get("gen") or 0)
        if gen != self.gen:
            self._reset(gen)
        rows = [row for row in reply.get("asns") or [] if isinstance(row, dict)]
        effective = next((row for row in rows if row.get("effective")), None)
        span = (effective or {}).get("range")
        if not isinstance(span, dict):
            self._remember(str(ip))
            return []
        try:
            lo = _unmap(ipaddress.ip_address(span["start"]))
            hi = _unmap(ipaddress.ip_address(span["end"]))
        except (KeyError, ValueError) as exc:
            raise GeoUnavailable("bad range: %s" % exc) from exc
        self._insert(ip.version, int(lo), int(hi), [{k: v for k, v in row.items() if k != "prefixes"} for row in rows])
        if expand:
            for row in rows:
                self._comps[int(row.get("asn") or 0)] = [str(p) for p in row.get("prefixes") or []]
        return rows

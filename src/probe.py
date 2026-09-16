from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
import time
import uuid

from nats.aio.client import Client as NATS
from nats.errors import NoRespondersError, TimeoutError as NatsTimeoutError

from store import redis_set

PROTOCOL_VERSION = 2
TTL_S = 60


def _headers(raw: list[str], host: str, cookies: list[str]) -> list[list[str]]:
    headers = [["host", host]]
    for item in raw:
        colon = item.find(":")
        if colon < 0:
            headers.append([item.strip().lower(), ""])
        else:
            headers.append([item[:colon].strip().lower(), item[colon + 1 :].strip()])
    if cookies:
        headers.append(["cookie", "; ".join(cookies)])
    return headers


def _placed(key: str, size: int) -> dict:
    return {"store": "probe", "driver": "redis", "key": key, "size": size}


def _place(request: dict, args: argparse.Namespace, headers: list[list[str]],
           query: str, body: bytes | None) -> None:
    if not args.redis:
        return

    base = "%s:%s:%s" % (args.node, request["rid"], request["phase"])
    needs: list[str] = []

    raw = json.dumps(headers, ensure_ascii=False).encode("utf-8")
    if redis_set(args.redis, base + ":hdr", raw, TTL_S):
        request["store"]["headers"] = _placed(base + ":hdr", len(raw))
        needs.append("headers")

    if query:
        raw = query.encode("utf-8")
        if redis_set(args.redis, base + ":arg", raw, TTL_S):
            request["store"]["args"] = _placed(base + ":arg", len(raw))
            needs.append("args")

    if body is not None and redis_set(args.redis, base, body, TTL_S):
        request["store"]["body"] = dict(
            _placed(base, len(body)),
            sha256=hashlib.sha256(body).hexdigest(),
            complete=True,
            truncated=False,
        )
        needs.append("body")

    request["needs"] = needs


def build(args: argparse.Namespace) -> dict:
    path, _, query = args.uri.partition("?")
    headers = _headers(args.header, args.host, args.cookie)
    body = args.body.encode("utf-8") if args.body is not None else None
    if body is not None:
        headers.append(["content-type", "application/json"])
        headers.append(["content-length", str(len(body))])
    request = {
        "v": PROTOCOL_VERSION,
        "rid": args.rid or secrets.token_hex(8),
        "ray": str(uuid.uuid4()),
        "phase": args.phase,
        "wave": args.wave,
        "inspector": args.inspector,
        "deadline_ms": args.deadline,
        "audit_subject": args.audit or None,
        "node": args.node,
        "conn": {
            "client_ip": args.ip,
            "client_port": 51544,
            "server_ip": "10.0.4.7",
            "server_port": 443,
            "tls": {"version": "TLSv1.3", "sni": args.host},
        },
        "http": {
            "method": args.method.upper(),
            "scheme": "https",
            "host": args.host,
            "uri": path or "/",
            "args_size": len(query.encode("utf-8")),
            "version": "HTTP/1.1",
        },
        "needs": [],
        "store": {"headers": None, "args": None, "body": None},
        "route": {"server_name": args.host, "location": "/", "profile": "default"},
        "score": {"total": args.score, "deny_at": 100},
    }
    _place(request, args, headers, query, body)
    if args.phase == "response":
        request["response"] = {
            "status": args.status,
            "headers": [["content-type", "application/json"]],
            "upstream_ms": 34,
        }
    return request


async def run(args: argparse.Namespace) -> int:
    nc = NATS()
    await nc.connect(
        servers=[part.strip() for part in args.server.split(",") if part.strip()],
        name="waf-probe",
        inbox_prefix="_INBOX.waf.%s" % args.node,
        max_reconnect_attempts=3,
    )
    failures = 0
    total = 0.0
    for i in range(args.count):
        request = build(args)
        if not args.quiet and i == 0:
            sys.stdout.write("--> %s\n%s\n" % (args.subject, json.dumps(request, ensure_ascii=False, indent=2)))
        started = time.perf_counter()
        try:
            msg = await nc.request(
                args.subject,
                json.dumps(request, ensure_ascii=False).encode("utf-8"),
                timeout=args.timeout / 1000.0,
            )
            took = (time.perf_counter() - started) * 1000.0
            total += took
            text = msg.data.decode("utf-8", errors="replace")
            try:
                shown = json.dumps(json.loads(text), ensure_ascii=False, indent=None if args.quiet else 2)
            except json.JSONDecodeError:
                shown = "%s   <-- not JSON, the module would drop this answer" % text
            sys.stdout.write("<-- %.1fms %s\n" % (took, shown if args.quiet else "\n" + shown))
            if args.expect:
                parsed = json.loads(text)
                got = parsed.get("verdict")
                if got != args.expect:
                    sys.stdout.write("expected verdict=%s, got %s\n" % (args.expect, got))
                    failures += 1
        except NoRespondersError:
            failures += 1
            took = (time.perf_counter() - started) * 1000.0
            sys.stdout.write(
                "<-- %.1fms ERROR: nobody is subscribed to subject \"%s\"\n" % (took, args.subject)
            )
        except NatsTimeoutError:
            failures += 1
            took = (time.perf_counter() - started) * 1000.0
            sys.stdout.write("<-- %.1fms ERROR: no answer within %sms\n" % (took, args.timeout))
        except Exception as exc:  # noqa: BLE001
            failures += 1
            took = (time.perf_counter() - started) * 1000.0
            sys.stdout.write("<-- %.1fms ERROR: %s\n" % (took, exc))
    if args.count > 1:
        sys.stdout.write(
            "\nrequests %s, errors %s, average %.1fms\n"
            % (args.count, failures, total / max(args.count - failures, 1))
        )
    await nc.drain()
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Module simulator for the vlai inspector.")
    parser.add_argument("--server", default=os.environ.get("NATS_URL", "nats://127.0.0.1:4222"))
    parser.add_argument("--subject", default=os.environ.get("WAF_VLAI_SUBJECT", "waf.req.vlai"))
    parser.add_argument("--inspector", default=os.environ.get("WAF_VLAI_NAME", "vlai"))
    parser.add_argument("--phase", default="request")
    parser.add_argument("--method", default="POST")
    parser.add_argument("--uri", default="/")
    parser.add_argument("--host", default="shop.example.com")
    parser.add_argument("--ip", default="203.0.113.42")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--cookie", action="append", default=[])
    parser.add_argument("--body", default=None)
    parser.add_argument("--status", type=int, default=200)
    parser.add_argument("--deadline", type=int, default=200)
    parser.add_argument("--wave", type=int, default=0)
    parser.add_argument("--score", type=int, default=0)
    parser.add_argument("--node", default="probe")
    parser.add_argument(
        "--redis",
        default=os.environ.get("REDIS_URL", ""),
        help="Redis to put headers, query string and body into; empty sends no objects",
    )
    parser.add_argument(
        "--audit",
        default="",
        help="audit_subject of the message; empty asks for no details",
    )
    parser.add_argument("--rid", default=None)
    parser.add_argument("--timeout", type=int, default=5000)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--expect", default=None, help="expected verdict, for the health check")
    args = parser.parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())

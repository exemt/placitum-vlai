from __future__ import annotations

import asyncio
import json
import signal
import threading
import time

from nats.aio.client import Client as NATS
from nats.aio.msg import Msg

import audit
import desired
import host as hostinfo
import logsink
import protocol
from admission import Gate
from classify import classify, load
import store
from config import load as load_config
from decide import evaluate, profile_of
from flow import WINDOW, Counter
from geo import Geo, GeoUnavailable, networked
from log import attach as attach_log
from log import log, set_level
from profiles import Registry, builtin
from pulse import build_pulse, new_inspector_id, status_subject

_infer_lock = threading.Lock()
_io_inspect = Counter()
_io_log = Counter()
_accepted = 0


def _classify(text: str) -> dict:
    with _infer_lock:
        return classify(text)


def _io_snapshot(sink: object) -> dict:
    io = {"inspect": _io_inspect.snapshot()}
    if sink is not None:
        io["log"] = _io_log.snapshot()
    return io


async def main() -> int:
    cfg = load_config()
    set_level(cfg["log_level"])
    store.configure(cfg["redis_url"])

    sink = None
    if cfg["log_ship"]:
        sink = logsink.LogSink(cfg["log_writer"], cfg["name"], _io_log)
        attach_log(sink)

    log("info", "loading model", model=cfg["model"], device=cfg["device"])
    load(cfg["model"], cfg["device"])
    log("info", "model ready", device=cfg["device"])

    nc = NATS()
    await nc.connect(
        servers=cfg["servers"],
        name="waf-inspector-%s" % cfg["name"],
        user=cfg["user"],
        password=cfg["pass"],
        token=cfg["token"],
        max_reconnect_attempts=-1,
        reconnect_time_wait=0.5,
    )

    ship = None
    if sink is not None:
        try:
            await logsink.ensure(nc)
        except Exception as exc:  # noqa: BLE001
            log("warn", "log stream", error=str(exc))
        sink.attach(nc)
        ship = asyncio.create_task(sink.run())
        log("info", "log stream", stream=logsink.STREAM,
            subject=logsink.subject(cfg["log_writer"]))

    log(
        "info",
        "connected",
        subject=cfg["subject"],
        queue=cfg["queue"],
        inspector=cfg["name"],
        queue_max=cfg["queue_depth"],
        queue_full=cfg["queue_full"],
        queue_expand=cfg["queue_expand"],
        conf=cfg["conf_path"] or None,
    )

    gate = Gate(cfg["queue_depth"], cfg["queue_full"], cfg["min_budget_ms"] / 1000.0)
    fills: dict[int, int] = {}

    registry = Registry(fallback=builtin(cfg["prior_rules"], cfg["queue_full"]))

    geo = Geo(cfg["geo_url"], cfg["geo_timeout_ms"] / 1000.0) if cfg["geo_url"] else None

    async def expand_bans(rows: list[dict]) -> tuple[list[dict], Exception | None]:
        out: list[dict] = []
        failed: Exception | None = None
        for row in rows:
            write = row.get("write") or "addr"
            if not networked(write):
                out.append({**row, "values": [row["value"]]})
                continue
            try:
                if geo is None:
                    raise GeoUnavailable("WAF_VLAI_GEO_URL is empty")
                got = await geo.write(write, row["value"])
            except GeoUnavailable as exc:
                failed = failed or exc
                continue
            if not got:
                log("warn", "list write skipped: coder knows nothing about the address",
                    set=row["dataset"], write=write, addr=row["value"])
                continue
            out.append({**row, "values": got})
        return out, failed

    async def publish_bans(rows: list[dict]) -> None:
        for row in rows:
            batch = row.get("values") or [row["value"]]
            event = {
                "v": 3,
                "set": row["dataset"],
                "op": "add",
                "ttl": row["ttl"],
                "origin": cfg["name"],
            }
            if len(batch) == 1:
                event["value"] = batch[0]
            else:
                event["values"] = batch
            if row.get("reason"):
                event["reason"] = row["reason"]
            try:
                msg = await nc.request(
                    "waf.sets.%s.event" % row["dataset"],
                    json.dumps(event, ensure_ascii=False).encode("utf-8"),
                    timeout=5,
                )
                reply = json.loads(msg.data.decode("utf-8", errors="replace") or "{}")
                if not reply.get("ok"):
                    log("warn", "list write rejected", set=row["dataset"],
                        value=batch[0], count=len(batch), error=reply.get("error"))
            except Exception as exc:  # noqa: BLE001
                log("warn", "list write failed: keeper unreachable",
                    set=row["dataset"], error=str(exc))

    async def process(msg: Msg) -> None:
        global _accepted
        started = time.perf_counter()
        fill = fills.pop(id(msg), 0)
        try:
            payload = msg.data.decode("utf-8", errors="replace")
            peek = _peek(payload)
            remaining = _remaining(peek, started)
            profile = registry.resolve(profile_of(peek))
            outcome = await asyncio.to_thread(
                evaluate,
                payload,
                name=cfg["name"],
                versions=cfg["versions"],
                min_budget_ms=cfg["min_budget_ms"],
                remaining_ms=remaining,
                classify_fn=_classify,
                profile=profile,
            )
            request = outcome.get("request") or {}
            reply = outcome["reply"]
            detail = outcome.get("detail") or {}

            overload_bans: list[dict] = []
            if profile is not None and profile.mode != "off" and reply.get("verdict") != "error":
                overload_asks = profile.asks_on("overload", fill=fill, shed=False)
                if overload_asks:
                    reply["actions"] = list(reply.get("actions") or []) + overload_asks
                client = str((request.get("conn") or {}).get("client_ip") or "")
                if client:
                    overload_bans = [
                        {
                            "dataset": row.dataset,
                            "value": client,
                            "write": row.write,
                            "ttl": row.ttl_s,
                            "reason": row.code or "VLAI_QUEUE_LIMIT",
                        }
                        for row in profile.bans_on("overload", fill=fill, shed=False)
                    ]
            if outcome.get("error"):
                log("warn", "message rejected", error=outcome["error"], bytes=len(msg.data))

            bans, geo_failed = await expand_bans((outcome.get("bans") or []) + overload_bans)
            if geo_failed is not None:
                log("error", "geo unavailable for a list write",
                    rid=request.get("rid"), error=str(geo_failed))
                reply = protocol.reply(
                    request,
                    request.get("inspector") or cfg["name"],
                    "error",
                    reason={"code": "VLAI_GEO_UNAVAILABLE"},
                )
                detail.setdefault("engine", {})["geo"] = str(geo_failed)

            if not msg.reply:
                log("error", "no reply subject in message", rid=request.get("rid"))
                return
            await msg.respond(json.dumps(reply, ensure_ascii=False).encode("utf-8"))
            took_ms = round((time.perf_counter() - started) * 1000.0, 3)
            _accepted += 1
            _io_inspect.add(bool(outcome.get("error")), took_ms)

            await publish_bans(bans)

            subject = protocol.audit_subject(request)
            if subject:
                try:
                    event = audit.build(
                        request,
                        reply,
                        findings=detail.get("findings"),
                        engine=detail.get("engine"),
                        engine_ms=took_ms,
                    )
                    await nc.publish(
                        subject,
                        json.dumps(event, ensure_ascii=False).encode("utf-8"),
                    )
                except Exception as exc:  # noqa: BLE001
                    log("warn", "audit publish failed", error=str(exc))
            log(
                "info",
                "verdict",
                rid=request.get("rid"),
                phase=request.get("phase"),
                inspector=request.get("inspector"),
                method=(request.get("http") or {}).get("method"),
                uri=(request.get("http") or {}).get("uri"),
                deadline_ms=request.get("deadline_ms"),
                verdict=reply.get("verdict"),
                score=reply.get("score"),
                reason=(reply.get("reason") or {}).get("code"),
                findings=len(detail.get("findings") or []),
                lists=len(outcome.get("bans") or []) or None,
                audit=subject or None,
                took_ms=took_ms,
            )
        except Exception as exc:  # noqa: BLE001
            took_ms = round((time.perf_counter() - started) * 1000.0, 3)
            _accepted += 1
            _io_inspect.add(True, took_ms)
            log("error", "handler failed", error=str(exc))
            if msg.reply:
                await msg.respond(
                    json.dumps(
                        {
                            "v": protocol.PROTOCOL_VERSION,
                            "rid": protocol.sniff_rid(
                                msg.data.decode("utf-8", errors="replace")
                            ),
                            "inspector": cfg["name"],
                            "verdict": "error",
                            "reason": {"code": "VLAI_INTERNAL_ERROR"},
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                )

    async def shed_many(msgs: list[Msg], code: str) -> None:
        for old in msgs:
            fills.pop(id(old), None)
            payload = old.data.decode("utf-8", errors="replace")
            await _reply_shed(old, cfg["name"], payload, code)
            log("warn", "shed", reason=code, queued=gate.queued(), queue_max=cfg["queue_depth"])

    async def worker() -> None:
        while True:
            msg, stale = await gate.take()
            if stale:
                await shed_many(stale, "VLAI_DEADLINE")
            if msg is None:
                continue
            try:
                await process(msg)
            finally:
                gate.done()

    async def admit(msg: Msg) -> None:
        payload = msg.data.decode("utf-8", errors="replace")
        peek = _peek(payload)
        remaining = _remaining(peek, time.perf_counter())
        profile = registry.resolve(profile_of(peek))
        wait_s = 0.0 if remaining is None else max(remaining, 0) / 1000.0
        overload = profile.overload if profile is not None else "shed"
        queued = gate.queued()
        fills[id(msg)] = 100 if queued >= gate.maxsize else queued * 100 // gate.maxsize
        outcome, evicted = await gate.submit(msg, wait_s, full=overload)
        if outcome:
            fills.pop(id(msg), None)
        if evicted:
            await shed_many(evicted, "VLAI_DEADLINE")
        if not outcome:
            return
        if outcome == "limit":
            off = profile is not None and profile.mode == "off"
            verdict = "allow" if off else "error"
            bans = profile.bans_on("overload") if profile is not None and not off else []
            asks = profile.asks_on("overload") if profile is not None and not off else []
            await _reply_shed(
                msg, cfg["name"], payload, "VLAI_QUEUE_LIMIT", verdict=verdict,
                actions=asks,
            )
            if bans:
                client = str(((peek or {}).get("conn") or {}).get("client_ip") or "")
                if client:
                    rows, geo_failed = await expand_bans([
                        {
                            "dataset": row.dataset,
                            "value": client,
                            "write": row.write,
                            "ttl": row.ttl_s,
                            "reason": row.code or "VLAI_QUEUE_LIMIT",
                        }
                        for row in bans
                    ])
                    if geo_failed is not None:
                        log("error", "geo unavailable for a list write", error=str(geo_failed))
                    await publish_bans(rows)
            log(
                "warn", "shed", reason="VLAI_QUEUE_LIMIT", verdict=verdict,
                profile=profile.name if profile is not None else None,
                lists=len(bans),
                queued=gate.queued(), queue_max=cfg["queue_depth"],
            )
            return
        await _reply_shed(msg, cfg["name"], payload, "VLAI_DEADLINE")
        log("warn", "shed", reason="VLAI_DEADLINE", queued=gate.queued(), queue_max=cfg["queue_depth"])

    async def sweeper() -> None:
        while True:
            await asyncio.sleep(0.01)
            stale = await gate.sweep()
            if stale:
                await shed_many(stale, "VLAI_DEADLINE")

    await nc.subscribe(
        cfg["subject"],
        queue=cfg["queue"],
        cb=admit,
        pending_msgs_limit=cfg["queue_depth"] + 4,
        pending_bytes_limit=4 * 1024 * 1024,
    )

    inspector_id = new_inspector_id()
    pulse_subject = status_subject(cfg["name"], inspector_id)

    async def heartbeat() -> None:
        while True:
            try:
                payload = build_pulse(
                    inspector_id=inspector_id,
                    name=cfg["name"],
                    subject=cfg["subject"],
                    queue=cfg["queue"],
                    device=cfg["device"],
                    host=hostinfo.collect(),
                    accepted=_accepted,
                    queued=gate.queued(),
                    queue_depth=cfg["queue_depth"],
                    workers=1,
                    io=_io_snapshot(sink),
                    window_s=WINDOW,
                    config_hash=registry.config_hash,
                    rev=registry.rev,
                    apply=registry.apply,
                    profiles=registry.names(),
                )
                await nc.publish(pulse_subject, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                log("warn", "heartbeat failed", error=str(exc))
            await asyncio.sleep(cfg["heartbeat_every_ms"] / 1000.0)

    work = asyncio.create_task(worker())
    sweep = asyncio.create_task(sweeper())
    beat = asyncio.create_task(heartbeat())
    generation = asyncio.create_task(desired.watch(nc, registry))
    log("info", "heartbeat on", subject=pulse_subject, id=inspector_id, every_ms=cfg["heartbeat_every_ms"])

    stop = asyncio.Event()

    def _stop(*_args: object) -> None:
        log("info", "draining")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            signal.signal(sig, lambda *_: _stop())

    await stop.wait()
    beat.cancel()
    sweep.cancel()
    generation.cancel()
    if ship is not None:
        ship.cancel()
        try:
            await ship
        except asyncio.CancelledError:
            pass
    await nc.drain()
    try:
        await asyncio.wait_for(gate.join(), timeout=5)
    except asyncio.TimeoutError:
        log("warn", "queue drain timeout", queued=gate.queued())
    work.cancel()
    return 0


async def _reply_shed(
    msg: Msg,
    name: str,
    payload: str,
    code: str,
    *,
    verdict: str = "error",
    actions: list | None = None,
) -> None:
    request, rid, _ = protocol.parse_request(payload)
    inspector = name
    if request:
        inspector = request.get("inspector") or name
        rid = request.get("rid") or rid
    body = protocol.reply(
        {"v": protocol.PROTOCOL_VERSION, "rid": rid},
        inspector,
        verdict,
        reason=({"code": code, "class": "overload"}
                if verdict == "error" else {"code": code}),
        actions=actions or None,
    )
    if not msg.reply:
        log("error", "no reply subject in message", rid=rid)
        return
    await msg.respond(json.dumps(body, ensure_ascii=False).encode("utf-8"))


def _peek(payload: str) -> dict | None:
    try:
        peek = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return peek if isinstance(peek, dict) else None


def _remaining(peek: dict | None, started: float) -> int | None:
    if peek is None or not isinstance(peek.get("deadline_ms"), (int, float)):
        return None
    spent = (time.perf_counter() - started) * 1000.0
    return int(peek["deadline_ms"] - spent)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

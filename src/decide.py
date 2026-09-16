from __future__ import annotations

from typing import Any, Callable

import audit
from profiles import Profile
from protocol import PROTOCOL_VERSION, parse_request, reply
from score import to_score
from text import MIN_CHARS, extract

ClassifyFn = Callable[[str], dict[str, Any]]


def _detail(
    engine: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {"findings": findings or [], "engine": engine or {}}


PERCENT_MIN = -100
PERCENT_MAX = 900


def profile_of(request: dict[str, Any] | None) -> str:
    route = (request or {}).get("route")
    name = route.get("profile") if isinstance(route, dict) else None
    return name if isinstance(name, str) and name else "default"


def _prior_ask(
    request: dict[str, Any], profile: Profile | None
) -> tuple[int, bool, list[dict[str, Any]]]:
    percent = 0
    skipped = False
    outcomes: list[dict[str, Any]] = []
    for entry in request.get("prior") or []:
        sender = entry.get("inspector")
        for act in entry.get("actions") or []:
            do = act.get("do")
            outcome = {
                "from": sender,
                "do": do,
                "apply": act.get("apply") or "request",
                "outcome": "no_rule",
            }
            if act.get("code"):
                outcome["code"] = act["code"]
            if act.get("delta") is not None:
                outcome["delta"] = act["delta"]

            rule = (
                profile.prior_match(sender, do, act.get("code") or "")
                if profile is not None and isinstance(sender, str)
                else None
            )
            if rule is not None and outcome["apply"] == "request":
                if do == "threshold" and isinstance(act.get("delta"), int):
                    percent += act["delta"]
                    outcome["took"] = act["delta"]
                    outcome["outcome"] = "applied"
                elif do == "skip":
                    skipped = True
                    outcome["outcome"] = "applied"
            outcomes.append(outcome)
    return max(PERCENT_MIN, min(PERCENT_MAX, percent)), skipped, outcomes


def _scale(score: int, percent: int) -> int:
    if percent == 0 or score <= 0:
        return max(score, 0)
    scaled = int(score * (1 + percent / 100) + 0.5)
    return max(0, min(scaled, 100))


def evaluate(
    payload: str,
    *,
    name: str,
    versions: list[int],
    min_budget_ms: int,
    remaining_ms: int | None,
    classify_fn: ClassifyFn,
    profile: Profile | None = None,
) -> dict[str, Any]:
    request, rid, error = parse_request(payload)
    if request is None:
        return {
            "error": error,
            "request": {"v": PROTOCOL_VERSION, "rid": rid, "inspector": name},
            "reply": reply(
                {"v": PROTOCOL_VERSION, "rid": rid},
                name,
                "error",
                reason={"code": "VLAI_UNPARSEABLE"},
            ),
            "detail": _detail({"error": error}),
        }

    inspector = request["inspector"]
    if request["v"] not in versions:
        return {
            "error": "unsupported schema version %s" % request["v"],
            "request": request,
            "reply": reply(
                request,
                inspector,
                "error",
                reason={"code": "VLAI_UNSUPPORTED_VERSION"},
            ),
            "detail": _detail({"version": request["v"]}),
        }

    if request["phase"] == "frame":
        return {
            "request": request,
            "reply": reply(
                request,
                inspector,
                "error",
                reason={"code": "VLAI_PHASE_NOT_SUPPORTED"},
            ),
            "detail": _detail({"phase": "frame"}),
        }

    if profile is None:
        return {
            "request": request,
            "reply": reply(
                request,
                inspector,
                "error",
                reason={"code": "VLAI_UNKNOWN_PROFILE"},
            ),
            "detail": _detail({"profile": profile_of(request)}),
        }

    def base_engine() -> dict[str, Any]:
        engine: dict[str, Any] = {}
        if profile is not None:
            engine["profile"] = profile.name
            if profile.mode != "enforce":
                engine["mode"] = profile.mode
            if profile.mode == "observe":
                engine["passive"] = True
        return engine

    if profile is not None and profile.mode == "off":
        return {
            "request": request,
            "reply": reply(request, inspector, "allow", reason={"code": "VLAI_PROFILE_OFF"}),
            "detail": _detail(base_engine()),
        }

    observe = profile is not None and profile.mode == "observe"

    def deliver(
        verdict: str,
        code: str,
        engine: dict[str, Any],
        *,
        score: int | None = None,
        asks: list[dict[str, Any]] | None = None,
        bans: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if asks:
            engine["asks"] = asks
        if bans:
            engine["bans"] = bans
        if observe and verdict != "allow":
            engine["would_verdict"] = verdict
            engine["would_code"] = code
            if score is not None:
                engine["would_score"] = score
            verdict, code, score = "allow", "VLAI_OBSERVE", None
        return {
            "request": request,
            "reply": reply(
                request,
                inspector,
                verdict,
                score=score,
                reason={"code": code},
                actions=asks or None,
            ),
            "detail": _detail(engine, findings),
            "bans": bans or [],
        }

    budget = request["deadline_ms"] if remaining_ms is None else remaining_ms
    if budget < min_budget_ms:
        engine = base_engine()
        engine["deadline_ms"] = request["deadline_ms"]
        engine["remaining_ms"] = budget
        return {
            "request": request,
            "reply": reply(request, inspector, "error", reason={"code": "VLAI_DEADLINE"}),
            "detail": _detail(engine),
        }

    percent, skipped, outcomes = _prior_ask(request, profile)

    def with_asks(engine: dict[str, Any]) -> dict[str, Any]:
        if outcomes:
            engine["actions"] = outcomes
        return engine

    if skipped:
        return deliver("allow", "VLAI_SKIPPED", with_asks(base_engine()))

    found = extract(request)
    text = found["text"]

    if found.get("unavailable"):
        engine = base_engine()
        engine["source"] = found["source"]
        engine["body"] = found.get("body")
        return {
            "request": request,
            "reply": reply(
                request, inspector, "error", reason={"code": "VLAI_STORE_UNAVAILABLE"}
            ),
            "detail": _detail(with_asks(engine)),
        }

    if len(text) < MIN_CHARS:
        engine = base_engine()
        engine["source"] = found["source"]
        engine["body"] = found.get("body")
        return {
            "request": request,
            "reply": reply(request, inspector, "allow", reason={"code": "VLAI_NO_TEXT"}),
            "detail": _detail(with_asks(engine)),
        }

    result = classify_fn(text)
    severity = result.get("severity")
    confidence = float(result.get("confidence") or 0)
    score = to_score(severity, confidence)
    engine = base_engine()
    engine.update(
        {
            "severity": severity,
            "confidence": confidence,
            "scores": result.get("scores"),
            "tokens": result.get("tokens"),
            "truncated": result.get("truncated"),
            "chars": result.get("chars") or len(text),
            "source": found["source"],
            "body": found.get("body"),
            "device": result.get("device"),
            "model": result.get("model"),
            "model_revision": result.get("model_revision"),
        }
    )
    if score <= 0:
        return {
            "request": request,
            "reply": reply(request, inspector, "allow", reason={"code": "VLAI_NO_TEXT"}),
            "detail": _detail(with_asks(engine)),
        }

    scaled = _scale(score, percent)
    if percent != 0:
        engine["score_raw"] = score
        engine["score_scale_percent"] = percent
        engine["score_scaled"] = scaled
    score = scaled
    with_asks(engine)

    asks = profile.asks_on("score", score) if profile is not None else []

    client = str((request.get("conn") or {}).get("client_ip") or "")
    bans = [
        {
            "dataset": row.dataset,
            "value": client,
            "write": row.write,
            "ttl": row.ttl_s,
            "reason": row.code or "VLAI_SCORE",
        }
        for row in (profile.bans_on("score", score) if profile is not None else [])
        if client
    ]

    return deliver(
        "score",
        "VLAI_SCORE",
        engine,
        score=score,
        asks=asks,
        bans=bans,
        findings=[
            audit.finding(
                "vlai-%s" % str(severity).lower(),
                audit.SEVERITY_OF.get(str(severity), audit.SEVERITY_INFO),
                "body" if str(found["source"]).startswith("body") else "args",
                confidence=confidence,
                evidence=text[:256],
            )
        ],
    )

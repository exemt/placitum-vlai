from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml


class _Yaml(yaml.SafeLoader):
    pass


_Yaml.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Yaml.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)

MODES = frozenset({"enforce", "observe", "off"})
OVERLOADS = frozenset({"wait", "shed"})
ONS = frozenset({"score", "overload"})
OVERLOAD_AT_MIN = 25
OVERLOAD_AT_MAX = 100

VERB_AXES = {
    "challenge": ("request",),
    "threshold": ("request",),
    "skip": ("request",),
    "mutate": ("request",),
    "reauth": ("session",),
    "note": ("request", "ip", "asn", "session"),
    "active": ("request", "conn"),
    "passive": ("request", "conn"),
    "vote": ("request", "conn"),
    "off": ("request", "conn"),
    "audit": ("request", "response"),
    "archive": ("request", "response"),
    "mark": ("request",),
    "score": ("request",),
}

AUDIT_VERBS = frozenset({"audit", "archive"})
CONTROL_VERBS = frozenset({"active", "passive", "vote", "off"})
ASK_PHASES = ("request", "response", "frame")

RECORD_VERBS = AUDIT_VERBS | {"mark", "score"}

MARKER_MAX = 128

ARCHIVE_OBJECTS = ("headers", "args", "body")

ARCHIVE_WHEN = ("allow", "deny")

ACCEPTS = frozenset({"threshold", "skip"})

DEFAULT_PROFILE = "default"


class ProfileError(ValueError):
    pass


def _fail(msg: str) -> None:
    raise ProfileError(msg)


@dataclass(frozen=True)
class PriorRule:
    sender: str
    accept: frozenset
    codes: frozenset

    def matches(self, sender: str, do: str, code: str) -> bool:
        if sender != self.sender or do not in self.accept:
            return False
        return not self.codes or code in self.codes


WRITES = ("addr", "net", "net_all", "asn")


@dataclass(frozen=True)
class Outcome:
    on: str
    to: str = ""
    do: str = ""
    apply: str = ""
    at: int | None = None
    below: bool = False
    eq: bool = False
    delta: int | None = None
    value: int | None = None
    counter: str = ""
    marker: str = ""
    group: str = ""
    phase: str = ""
    set_: str = ""
    objects: tuple[tuple[str, dict[str, object]], ...] = ()
    when: tuple[str, ...] = ()
    dataset: str = ""
    write: str = "addr"
    ttl_s: int = 0
    code: str = ""

    def fires_overload(self, fill: int, shed: bool) -> bool:
        if shed:
            return True
        at = OVERLOAD_AT_MAX if self.at is None else self.at
        return at < OVERLOAD_AT_MAX and fill >= at

    def fires(self, score: int) -> bool:
        if self.at is None:
            return False
        if self.eq:
            return score == self.at
        if self.below:
            return score < self.at
        return score >= self.at

    def ask(self) -> dict:
        out: dict = {"do": self.do, "apply": self.apply}
        if self.to:
            out["to"] = self.to
        if self.delta is not None:
            out["delta"] = self.delta
        if self.value is not None:
            out["value"] = self.value
        if self.counter:
            out["counter"] = self.counter
        if self.marker:
            out["marker"] = self.marker
        if self.group:
            out["group"] = self.group
        if self.phase:
            out["phase"] = self.phase
        if self.set_:
            out["set"] = self.set_
        if self.do in AUDIT_VERBS and self.set_ == "on":
            if self.do == "archive" and self.ttl_s > 0:
                out["ttl"] = self.ttl_s
            if self.do == "archive" and self.when:
                out["when"] = list(self.when)
            for name, spec in self.objects:
                out[name] = dict(spec)
        if self.code:
            out["code"] = self.code
        return out


@dataclass(frozen=True)
class Profile:
    name: str
    mode: str = "enforce"
    overload: str = "shed"
    prior: tuple = ()
    outcomes: tuple = ()

    def prior_match(self, sender: str, do: str, code: str) -> PriorRule | None:
        for rule in self.prior:
            if rule.matches(sender, do, code):
                return rule
        return None

    def asks_on(
        self, on: str, score: int = 0, *, fill: int = OVERLOAD_AT_MAX, shed: bool = True
    ) -> list[dict]:
        out = []
        for outcome in self.outcomes:
            if outcome.on != on or not outcome.do:
                continue
            if on == "score" and not outcome.fires(score):
                continue
            if on == "overload" and not outcome.fires_overload(fill, shed):
                continue
            out.append(outcome.ask())
        return out

    def bans_on(
        self, on: str, score: int = 0, *, fill: int = OVERLOAD_AT_MAX, shed: bool = True
    ) -> list[Outcome]:
        out = []
        for outcome in self.outcomes:
            if outcome.on != on or not outcome.dataset:
                continue
            if on == "score" and not outcome.fires(score):
                continue
            if on == "overload" and not outcome.fires_overload(fill, shed):
                continue
            out.append(outcome)
        return out


def builtin(prior_senders, queue_full: str) -> Profile:
    rules = tuple(
        PriorRule(
            sender=name,
            accept=frozenset({"threshold"}),
            codes=frozenset(),
        )
        for name in (prior_senders or ())
    )
    return Profile(
        name=DEFAULT_PROFILE,
        mode="enforce",
        overload="wait" if queue_full == "wait" else "shed",
        prior=rules,
    )


CODE_MAX = 64


def _code_ok(code: str) -> bool:
    if not code or len(code) > CODE_MAX:
        return False
    if not ("A" <= code[0] <= "Z"):
        return False
    return all("A" <= ch <= "Z" or "0" <= ch <= "9" or ch == "_" for ch in code)


def _counter_name_ok(name: str) -> bool:
    if not name or not name[0].isalnum():
        return False
    return all(ch.isalnum() or ch in "._-" for ch in name)


def _as_int(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("%s must be an integer" % where)
    return value


def _ttl_seconds(raw, where: str) -> int:
    if raw is None:
        return 0
    text = str(raw).strip().lower()
    if not text:
        return 0
    mult = 1
    if text.endswith("s"):
        text = text[:-1]
    elif text.endswith("m"):
        mult, text = 60, text[:-1]
    elif text.endswith("h"):
        mult, text = 3600, text[:-1]
    elif text.endswith("d"):
        mult, text = 86400, text[:-1]
    try:
        seconds = int(text.strip())
    except ValueError:
        seconds = -1
    if seconds < 0:
        _fail("%s: bad ttl %r" % (where, raw))
    return seconds * mult


def _prior_rule(raw: dict, where: str) -> PriorRule:
    sender = str(raw.get("from") or "").strip()
    if sender in ("", "*"):
        _fail("%s: from needs a named sender: both verbs can weaken" % where)

    accept = raw.get("accept") or []
    if not isinstance(accept, list) or not accept:
        _fail("%s: accept is required" % where)
    for verb in accept:
        if verb not in ACCEPTS:
            _fail("%s: %r is not ours to apply" % (where, verb))

    codes = raw.get("codes") or []
    if not isinstance(codes, list):
        _fail("%s: codes must be a list" % where)
    codes = [str(code).strip().upper() for code in codes]
    for code in codes:
        if not _code_ok(code):
            _fail("%s: code %r is not [A-Z][A-Z0-9_]{0,63}" % (where, code))

    return PriorRule(
        sender=sender,
        accept=frozenset(accept),
        codes=frozenset(codes),
    )


def _outcome(raw: dict, where: str) -> Outcome:
    on = str(raw.get("on") or "score")
    if on not in ONS:
        _fail("%s.on must be score or overload" % where)

    at = raw.get("at")
    below = bool(raw.get("below", False))
    eq = bool(raw.get("eq", False))
    if on == "score":
        if at is None:
            _fail("%s: on: score needs at" % where)
        at = _as_int(at, where + ".at")
        if at < 0 or at > 100:
            _fail("%s.at is out of 0..100" % where)
        if below and eq:
            _fail("%s: below and eq are mutually exclusive" % where)
    elif on == "overload":
        if at is not None:
            at = _as_int(at, where + ".at")
            if at < OVERLOAD_AT_MIN or at > OVERLOAD_AT_MAX:
                _fail("%s.at is out of %d..%d percent of the queue"
                      % (where, OVERLOAD_AT_MIN, OVERLOAD_AT_MAX))
        if below or eq:
            _fail("%s: below and eq are only for on: score" % where)

    code = str(raw.get("code") or "").strip()
    if code and not _code_ok(code):
        _fail("%s.code is not a valid reason code" % where)

    do = str(raw.get("do") or "").strip()
    dataset = str(raw.get("list") or "").strip()
    if do and dataset:
        _fail("%s: do and list are mutually exclusive" % where)
    if not do and not dataset:
        _fail("%s: neither do nor list" % where)

    if dataset:
        if not _counter_name_ok(dataset):
            _fail("%s: bad dataset name %r" % (where, dataset))
        write = str(raw.get("write") or "addr").strip()
        if write not in WRITES:
            _fail("%s: write must be addr, net, net_all or asn" % where)
        ttl_s = _ttl_seconds(raw.get("ttl"), where)
        if ttl_s <= 0:
            _fail("%s: list needs ttl" % where)
        return Outcome(
            on=on,
            at=at,
            below=below,
            eq=eq,
            dataset=dataset,
            write=write,
            ttl_s=ttl_s,
            code=code,
        )

    to = str(raw.get("to") or "").strip()
    if to in ("", "*") and do not in RECORD_VERBS:
        _fail("%s: to is empty" % where)
    if to not in ("", "*") and do in RECORD_VERBS:
        _fail("%s: %s takes no to: the module writes the route's own record" % (where, do))

    axes = VERB_AXES.get(do)
    if axes is None:
        _fail("%s.do is not a verb of the actions channel" % where)

    apply_axis = str(raw.get("apply") or "").strip()
    if apply_axis == "" and (len(axes) == 1 or do in RECORD_VERBS):
        apply_axis = axes[0]
    if apply_axis not in axes:
        _fail("%s: verb %s does not take apply %r" % (where, do, apply_axis))

    delta = raw.get("delta")
    if delta is not None:
        delta = _as_int(delta, where + ".delta")
        if do != "threshold":
            _fail("%s: delta is only for threshold" % where)
        if delta < -100 or delta > 900:
            _fail("%s.delta is out of -100..900 percent" % where)
    if do == "threshold" and not delta:
        _fail("%s: threshold needs a non-zero delta" % where)

    value = raw.get("value")
    if value is not None:
        value = _as_int(value, where + ".value")
        if do not in ("note", "score"):
            _fail("%s: value is only for note and score" % where)
        if value < -100 or value > 100:
            _fail("%s.value is out of -100..100 percent" % where)
    if do == "note" and not value:
        _fail("%s: note needs a non-zero value" % where)
    if do == "score" and not value:
        _fail("%s: score needs a non-zero value" % where)

    counter = str(raw.get("counter") or "").strip()
    if counter:
        if do != "note":
            _fail("%s: counter is only for note" % where)
        if not _counter_name_ok(counter):
            _fail("%s: bad counter name %r" % (where, counter))

    marker = str(raw.get("marker") or "")
    if do == "mark":
        _check_marker(marker, where)
    elif marker:
        _fail("%s: marker is only for mark" % where)

    group = str(raw.get("group") or "").strip()
    set_ = str(raw.get("set") or "").strip().lower()
    if do == "mutate":
        if not group:
            _fail("%s: mutate needs a group" % where)
        if not _counter_name_ok(group):
            _fail("%s: bad group name %r" % (where, group))
        if set_ not in ("on", "off"):
            _fail("%s: mutate needs set: on or off" % where)
    elif group:
        _fail("%s: group is only for mutate" % where)

    phase = str(raw.get("phase") or "").strip()
    if phase:
        if do not in CONTROL_VERBS:
            _fail("%s: phase is only for active, passive, vote and off" % where)
        if phase not in ASK_PHASES:
            _fail("%s: phase must be request, response or frame, got %r" % (where, phase))
        if apply_axis == "conn" and phase != "frame":
            _fail("%s: apply conn needs phase frame" % where)

    ttl_s = _ttl_seconds(raw.get("ttl"), where) if raw.get("ttl") is not None else 0
    objects = _record_objects(raw, where, do == "audit")
    when = _archive_when(raw.get("when"), where)
    if do in AUDIT_VERBS:
        if set_ not in ("on", "off"):
            _fail("%s: %s needs set: on or off" % (where, do))
        if set_ == "off" and (objects or ttl_s or when):
            _fail("%s: ttl, when and objects are only for set on" % where)
        if do == "audit" and (ttl_s or when):
            _fail("%s: ttl and when are only for archive" % where)
        if apply_axis == "response" and any(name == "args" for name, _ in objects):
            _fail("%s: args has no meaning for the response record" % where)
    elif objects or ttl_s or when:
        _fail(
            "%s: ttl, when, headers, args and body are only for audit and archive"
            % where
        )
    elif set_ and do != "mutate":
        _fail("%s: set is only for mutate, audit and archive" % where)

    return Outcome(
        on=on,
        to=to,
        do=do,
        apply=apply_axis,
        at=at,
        below=below,
        eq=eq,
        delta=delta,
        value=value,
        counter=counter,
        marker=marker,
        group=group,
        phase=phase,
        set_=set_,
        objects=objects,
        when=when,
        ttl_s=ttl_s,
        code=code,
    )


def _check_marker(marker: str, where: str) -> None:
    if not marker:
        _fail("%s: mark needs a marker" % where)
    if len(marker.encode("utf-8")) > MARKER_MAX:
        _fail("%s: marker is longer than %d bytes" % (where, MARKER_MAX))
    for ch in marker:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            _fail("%s: marker has a control character" % where)
    if marker != marker.strip(" "):
        _fail("%s: marker has a leading or trailing space" % where)


def _archive_when(raw: object, where: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        _fail("%s.when must be a list" % where)
    seen: set[str] = set()
    for item in raw:
        name = str(item).strip().lower()
        if name not in ARCHIVE_WHEN:
            _fail("%s.when accepts only allow and deny, got %r" % (where, item))
        if name in seen:
            _fail("%s.when lists %r twice" % (where, name))
        seen.add(name)
    return tuple(name for name in ARCHIVE_WHEN if name in seen)


def _record_objects(raw: dict, where: str, audit: bool) -> tuple[tuple[str, dict[str, object]], ...]:
    out: list[tuple[str, dict[str, object]]] = []
    for name in ARCHIVE_OBJECTS:
        spec_raw = raw.get(name)
        if spec_raw is None:
            continue
        if not isinstance(spec_raw, dict):
            _fail("%s.%s must be a mapping" % (where, name))
        spec: dict[str, object] = {}
        set_ = str(spec_raw.get("set") or "").strip().lower()
        if set_:
            if set_ not in ("on", "off"):
                _fail("%s.%s.set must be on or off" % (where, name))
            spec["set"] = set_
        limit = spec_raw.get("limit")
        limit = _as_int(limit, "%s.%s.limit" % (where, name)) if limit is not None else 0
        if limit < 0:
            _fail("%s.%s.limit must not be negative" % (where, name))
        if limit:
            spec["limit"] = limit
        source = str(spec_raw.get("source") or "").strip().lower()
        if source:
            if source not in ("store", "original"):
                _fail("%s.%s.source must be store or original" % (where, name))
            spec["source"] = source
        out.append((name, spec))
    return tuple(out)


def parse_profile(name: str, text: str) -> Profile:
    try:
        raw = yaml.load(text, Loader=_Yaml)  # noqa: S506
    except yaml.YAMLError as exc:
        _fail("%s: profile.yaml does not parse: %s" % (name, exc))

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        _fail("%s: profile.yaml is not a mapping" % name)

    mode = str(raw.get("mode") or "enforce")
    if mode not in MODES:
        _fail("%s: mode must be enforce, observe or off" % name)

    overload = str(raw.get("overload") or "shed")
    if overload not in OVERLOADS:
        _fail("%s: overload must be wait or shed" % name)

    trigger = raw.get("trigger") or {}
    if not isinstance(trigger, dict):
        _fail("%s: trigger is not a mapping" % name)
    prior_raw = trigger.get("prior") or []
    if not isinstance(prior_raw, list):
        _fail("%s: trigger.prior is not a list" % name)
    prior = tuple(
        _prior_rule(row if isinstance(row, dict) else {}, "%s: trigger.prior[%d]" % (name, i))
        for i, row in enumerate(prior_raw)
    )

    outcomes_raw = raw.get("outcomes") or []
    if not isinstance(outcomes_raw, list):
        _fail("%s: outcomes is not a list" % name)
    outcomes = tuple(
        _outcome(row if isinstance(row, dict) else {}, "%s: outcomes[%d]" % (name, i))
        for i, row in enumerate(outcomes_raw)
    )

    return Profile(name=name, mode=mode, overload=overload, prior=prior, outcomes=outcomes)


@dataclass
class Registry:
    fallback: Profile
    profiles: dict = field(default_factory=dict)
    config_hash: str = ""
    rev: int = 0
    apply: str = ""
    error: str = ""

    def resolve(self, name) -> Profile | None:
        if not self.profiles:
            return self.fallback

        return self.profiles.get(
            name if isinstance(name, str) and name else DEFAULT_PROFILE
        )

    def apply_generation(self, profiles: dict, config_hash: str, rev: int) -> None:
        self.profiles = profiles
        self.config_hash = config_hash
        self.rev = rev
        self.apply = "ok"
        self.error = ""

    def reject_generation(self, reason: str) -> None:
        self.apply = "apply_failed"
        self.error = reason

    def names(self) -> list:
        return sorted(self.profiles) if self.profiles else []

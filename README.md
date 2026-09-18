# Placitum vlai

English · [Русский](README.ru.md)

Placitum inspector in Python. It rates the severity of a vulnerability from its Russian description.

It is neither a detector nor a vulnerability scanner. The input is an advisory-style description that
somebody has already written (FSTEC, BDU), the output is a `score` from 0 to 100. The model does not
look at code and does not search for SQL injection: it reads text only. The module decides by the
route threshold; the inspector itself never answers `deny`.

```
module ──► waf.req.vlai ──► vlai ──► score | allow | error
                              │
                              ├── text: description field of the body or the query string
                              └── model: ruRoberta-large, Low…Critical × confidence
```

## Model

[CIRCL/vulnerability-severity-classification-russian-ruRoberta-large](https://huggingface.co/CIRCL/vulnerability-severity-classification-russian-ruRoberta-large),
licensed CC-BY-4.0. Origin, dataset and paper are listed in [SOURCE](SOURCE).

**The weights are not in the image.** The process downloads them from Hugging Face on the first
start, about 1.4 GB, and keeps them in the `/var/lib/waf/vlai` volume. The revision is pinned in
`src/classify.py` and matches `SOURCE`: an installation today and one in a month get the same
weights, and a replaced head of the model repository never reaches you silently.

On a GPU a short paragraph takes about 20 ms and the full 512-token window about 90 ms. On a CPU it
takes hundreds of milliseconds, so for a 15–25 ms wave only a GPU and a short text will do.

## How it rates

The text is taken from the first place that has it: the `description`, `text`, `advisory`, `details`
or `описание` field of a JSON body, the raw body, the same fields of the query string. The body and
the query string are read from the buffer by locator. The text is cut at 3072 characters, and the
model window is 512 tokens.

The model returns a class and its confidence. The score is `100 × weight × confidence`, with weights
Low 0.25, Medium 0.5, High 0.75 and Critical 1: Critical with full confidence gives 100, Low with
full confidence gives 25.

| Verdict | Code | When |
| --- | --- | --- |
| `score` | `VLAI_SCORE` | the model rated the text |
| `allow` | `VLAI_NO_TEXT` | there is no text, or it is shorter than 4 characters |
| `allow` | `VLAI_SKIPPED` | a neighbour's `skip` request switched the check off |
| `allow` | `VLAI_PROFILE_OFF` | the profile is off |
| `allow` | `VLAI_OBSERVE` | the profile observes; the verdict it would give is in the audit |
| `error` | `VLAI_STORE_UNAVAILABLE` | the buffer did not return the body or the query string |
| `error` | `VLAI_UNKNOWN_PROFILE` | the route names a profile that is not in the generation |
| `error` | `VLAI_DEADLINE` | less budget left than `VLAI_MIN_BUDGET_MS` |
| `error` | `VLAI_QUEUE_LIMIT` | the local queue is full |
| `error` | `VLAI_GEO_UNAVAILABLE` | a `net`, `net_all` or `asn` write needs the geo coder, and it does not answer |
| `error` | `VLAI_UNPARSEABLE`, `VLAI_UNSUPPORTED_VERSION`, `VLAI_PHASE_NOT_SUPPORTED`, `VLAI_INTERNAL_ERROR` | a broken message, an unknown schema version, a WebSocket frame, an internal failure |

After `error` the route decides with `waf_exception <phase> inspector pass|deny`. The audit event
(`kind=inspector`) carries the class, the confidence, the class scores, the token count and whether
the text was cut.

## Profiles

Profiles come from the controller as a generation (key `policy/vlai` in `WAF_DESIRED`) and live in
memory only. A broken generation does not replace the current one and shows as `apply_failed` in the
presence frame. The profile is chosen by `route.profile`; an empty tag means `default`. Until the
first generation arrives, a built-in profile works: `enforce`, `threshold` requests accepted from the
senders in `WAF_VLAI_PRIOR`, queue behaviour from `queue_full`.

```yaml
mode: enforce                  # printed by the controller; the call mode is set on the route (waf_inspect … mode=)
overload: shed                 # shed | wait: answer at once or wait in the full queue

trigger:
  prior:                       # whose requests to apply; without a rule they only reach the audit
    - from: ip                 # both verbs weaken the check, so the sender is always named
      accept: [threshold, skip]
      codes: [IP_ALLOWLIST]    # empty means any reason

outcomes:
  - on: score                  # the score that goes to the module
    at: 60                     # below: true compares the other way, eq: true means exactly
    to: captcha
    do: challenge
    code: VLAI_HOT
  - on: overload               # the queue is at least 60% full, or the request was dropped
    at: 60                     # 25..100; without it only a dropped request counts
    to: counter
    do: note
    apply: ip
    value: 20
    counter: abuse
    code: VLAI_OVERLOAD
  - on: overload
    list: shed_clients         # a live set
    write: addr                # addr | net | net_all | asn
    ttl: 10m
```

**Mode.** `observe` does all the same work (buffer, inference, neighbour factors) but gives the
module `allow` with `VLAI_OBSERVE` and leaves the decision in the audit: `engine.passive: true`,
`would_verdict`, `would_code`, `would_score`. Requests and list writes still go out, because
observing mutes only the verdict. `off` answers `allow` with `VLAI_PROFILE_OFF` and runs no
inference.

**Neighbour requests** (`trigger.prior`). Two verbs of the action channel apply here. `threshold`
scales the score that goes to the module by `1 + delta/100` (the sum is kept within −100..900; the
route thresholds do not move). `skip` switches the check off before the buffer and the inference
and answers `allow` with `VLAI_SKIPPED`; for the most expensive inspector this saves the most. The
outcome of each request and the `score_raw`, `score_scale_percent` and `score_scaled` values go to
the audit event.

**Outcome rows** (`outcomes`). `on: score` compares `at` with the score that goes to the module,
after neighbour factors. `on: overload` fires when the queue is at least `at` percent full as the
request joins it, and on a request dropped because the queue is full; the requests then travel in
that `error` answer. Each row does one thing: `to` with `do` signals a neighbour, `list` with `ttl`
writes the client into a live set. `write` says what to write: the address (`addr`, the default),
its effective announcement (`net`), every announcement over it (`net_all`) or the whole autonomous
system (`asn`). Announcements come from the geo coder over HTTP (`WAF_VLAI_GEO_URL`) within the
message budget. The write goes to keeper as `waf.sets.<set>.event` after the answer.

## Trying the model without the bus

```sh
docker run --rm -v vlai-checkpoint:/var/lib/waf/vlai placitum/vlai \
  classify "Удалённый злоумышленник может выполнить произвольный код."
```

The text says "A remote attacker can execute arbitrary code". `serve` starts an HTTP server with
`POST /classify/severity`, the same contract as CIRCL ML-Gateway, on `VLAI_PORT` (8080 by default).

What it needs, the settings and the first model download are in [INSTALL.md](INSTALL.md).

## License

Code: [Placitum License Agreement](LICENSE.md). A Russian translation is in
[LICENSE.ru.md](LICENSE.ru.md); the English text is the legally binding one. Model: CC-BY-4.0 by its
authors (CIRCL), see [SOURCE](SOURCE).

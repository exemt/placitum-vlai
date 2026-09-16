# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus and needs no
address or service. Install it where routes carry Russian vulnerability descriptions that need a
rating; it is an optional component.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.vlai` queue, audit, log, profile generations |
| Exchange Redis | yes | the request body travels in the exchange, not in the message: without it every such request gets `error` |
| Hugging Face access | on the first start | downloading the weights, about 1.4 GB |
| `keeper` | for list writes | receives `waf.sets.<set>.event` |
| `geo` | for `net`, `net_all` and `asn` writes | over HTTP; without it such writes answer `error` |
| Controller | no | profiles; the built-in profile works until the first generation |

**Memory:** 4 GB per container, since the large model lives in process memory. **A GPU** gives
latencies that fit a wave; the CPU image works, but slowly.

## First model download

The weights go to the `/var/lib/waf/vlai` volume, `HF_HOME` is inside it. The first start downloads
them and takes a while, which is why the `HEALTHCHECK` has a long `start-period`. The volume survives
container re-creation, and the next start reads the weights from disk.

**Without internet access**, download the weights in advance:

```sh
hf download CIRCL/vulnerability-severity-classification-russian-ruRoberta-large \
  --revision 5de95b34808c905f912eb6fd11fdbd64717c57e3 --cache-dir ./hub
```

Copy the contents of `./hub` to `/var/lib/waf/vlai/hf/hub` in the volume and set `HF_HUB_OFFLINE=1`.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus; several addresses are comma-separated |
| `NATS_USER`, `NATS_PASS`, `NATS_TOKEN` | empty | bus authentication |
| `REDIS_URL` | from `inspector.conf` | exchange: body and query string by locator; the health check probe reads only this variable |
| `WAF_VLAI_SUBJECT` | `waf.req.vlai` | subscription |
| `WAF_VLAI_NAME` | `vlai` | name in the inspector registry |
| `WAF_VLAI_QUEUE` | the name | queue group on the bus |
| `WAF_VLAI_VERSIONS` | `2` | accepted message schema versions |
| `WAF_VLAI_LOG` | `info` | starting log level |
| `VLAI_DEVICE` | `cpu`; `cuda` in the CUDA image | torch device |
| `VLAI_MODEL` | the CIRCL model | your own model instead of the shipped one |
| `VLAI_MODEL_REVISION` | the `SOURCE` revision for the shipped model | weights revision; pin your own model with its own |
| `VLAI_MIN_BUDGET_MS` | `8` | inference does not start with less budget left |
| `WAF_VLAI_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_VLAI_QUEUE_DEPTH`, `WAF_VLAI_QUEUE_FULL`, `WAF_VLAI_QUEUE_EXPAND` | `256`, `drop`, `off` | queue and overflow behaviour; the same through `inspector.conf` |
| `WAF_VLAI_PRIOR` | empty | senders whose `threshold` requests the built-in profile accepts, comma-separated (`ip,action`); `*` is rejected |
| `WAF_VLAI_GEO_URL` | empty | geo coder HTTP address for `net`, `net_all` and `asn` writes |
| `WAF_VLAI_GEO_TIMEOUT` | `500` | coder timeout within the message budget: milliseconds, or `500ms`, `0.5s` |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_LOG_SHIP`, `WAF_LOG_WRITER` | `on`, host name | whether the process log goes to the bus, and under which name |

## Docker Compose

```yaml
services:
  inspector-vlai:
    image: placitum/vlai
    mem_limit: 4g
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      WAF_VLAI_GEO_URL: http://geo:8092
      VLAI_DEVICE: cpu
    volumes:
      - vlai-checkpoint:/var/lib/waf/vlai
    depends_on: [nats, redis]

volumes:
  vlai-checkpoint:
```

For a GPU use the `placitum/vlai:cuda` image built from `deploy/Dockerfile.cuda`, `VLAI_DEVICE: cuda`
and device access (`deploy.resources.reservations.devices` in compose, or `--gpus all`).

## Checking

The inspector has no port of its own, so it is checked the way the module works, with the probe
from the image:

```sh
docker exec <container> python /app/src/probe.py --redis redis://redis:6379 \
  --body '{"description":"Удалённый злоумышленник может выполнить произвольный код."}'
```

Expect `verdict: score` with `VLAI_SCORE`. Without `--redis` the probe puts nothing into the exchange
and gets `allow` with `VLAI_NO_TEXT`: a meaningful answer, but not a model check.

## Pitfalls

- **Without `REDIS_URL` the container stays `unhealthy` while the inspector works.** The probe puts
  the body into the exchange and takes the address only from the environment; it does not read the
  `redis` block of `inspector.conf`.
- **The first start is long.** While the weights download there is no subscription and the container
  is not `healthy`; that is not a failure.
- **Profiles use YAML 1.2 booleans.** Only `true` and `false` are booleans, so `on:` and `mode: off`
  mean exactly what they say.

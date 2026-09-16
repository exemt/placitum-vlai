# Установка

[English](INSTALL.md) · Русский

Инспектор не слушает сеть: он подписчик очереди на шине, и ни адрес, ни сервис ему не нужны. Ставят
его там, где на маршрутах есть русские описания уязвимостей и нужна их оценка; это необязательный
компонент.

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS | да | очередь `waf.req.vlai`, аудит, журнал, поколение профилей |
| Redis: обменник | да | тело запроса едет в обменнике, а не в сообщении: без него каждый такой запрос получает `error` |
| Доступ к Hugging Face | при первом старте | загрузка весов, около 1,4 ГБ |
| `keeper` | для записей в наборы | принимает `waf.sets.<набор>.event` |
| `geo` | для записей `net`, `net_all` и `asn` | по HTTP; без него такие записи отвечают `error` |
| Контроллер | нет | профили; до первого поколения работает встроенный профиль |

**Память:** 4 ГБ на контейнер — модель large живёт в памяти процесса. **GPU** даёт задержки, годные
для волны; CPU-образ рабочий, но медленный.

## Первая загрузка модели

Веса ложатся в том `/var/lib/waf/vlai`, `HF_HOME` внутри него. Первый старт их качает и поэтому
долгий — отсюда длинный `start-period` у `HEALTHCHECK`. Том переживает пересоздание контейнера, и
следующий старт берёт веса с диска.

**Без доступа в интернет** веса скачивают заранее:

```sh
hf download CIRCL/vulnerability-severity-classification-russian-ruRoberta-large \
  --revision 5de95b34808c905f912eb6fd11fdbd64717c57e3 --cache-dir ./hub
```

Содержимое `./hub` кладут в `/var/lib/waf/vlai/hf/hub` тома и задают `HF_HUB_OFFLINE=1`.

## Настройки

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | шина; несколько адресов — через запятую |
| `NATS_USER`, `NATS_PASS`, `NATS_TOKEN` | пусто | аутентификация на шине |
| `REDIS_URL` | из `inspector.conf` | обменник: тело и строка запроса по локаторам; проба healthcheck читает только эту переменную |
| `WAF_VLAI_SUBJECT` | `waf.req.vlai` | подписка |
| `WAF_VLAI_NAME` | `vlai` | имя в реестре инспекторов |
| `WAF_VLAI_QUEUE` | имя | очередь шины |
| `WAF_VLAI_VERSIONS` | `2` | версии схемы сообщения, которые процесс принимает |
| `WAF_VLAI_LOG` | `info` | стартовый уровень журнала |
| `VLAI_DEVICE` | `cpu`; в CUDA-образе `cuda` | устройство torch |
| `VLAI_MODEL` | модель CIRCL | своя модель вместо поставочной |
| `VLAI_MODEL_REVISION` | ревизия из `SOURCE` для поставочной модели | ревизия весов; свою модель пинуйте своей ревизией |
| `VLAI_MIN_BUDGET_MS` | `8` | при меньшем остатке бюджета инференс не стартует |
| `WAF_VLAI_CONF` | `inspector.conf` в рабочем каталоге, затем `/app/inspector.conf` | очередь и адрес Redis |
| `WAF_VLAI_QUEUE_DEPTH`, `WAF_VLAI_QUEUE_FULL`, `WAF_VLAI_QUEUE_EXPAND` | `256`, `drop`, `off` | очередь и поведение при переполнении; то же через `inspector.conf` |
| `WAF_VLAI_PRIOR` | пусто | отправители, чьи просьбы `threshold` принимает встроенный профиль, через запятую (`ip,action`); `*` не принимается |
| `WAF_VLAI_GEO_URL` | пусто | HTTP-адрес кодера гео для записей `net`, `net_all` и `asn` |
| `WAF_VLAI_GEO_TIMEOUT` | `500` | таймаут кодера в бюджете сообщения: миллисекунды числом либо `500ms`, `0.5s` |
| `WAF_HEARTBEAT_EVERY` | `4s` | период кадра присутствия |
| `WAF_LOG_SHIP`, `WAF_LOG_WRITER` | `on`, имя машины | уезжает ли журнал процесса на шину и под каким именем |

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

Для GPU — образ `placitum/vlai:cuda` из `deploy/Dockerfile.cuda`, `VLAI_DEVICE: cuda` и доступ к
устройству (`deploy.resources.reservations.devices` в compose или `--gpus all`).

## Проверка

Своего порта у инспектора нет, поэтому проверяют его тем же путём, что работает модуль, — пробой из
образа:

```sh
docker exec <контейнер> python /app/src/probe.py --redis redis://redis:6379 \
  --body '{"description":"Удалённый злоумышленник может выполнить произвольный код."}'
```

Ожидается `verdict: score` с кодом `VLAI_SCORE`. Без `--redis` проба не кладёт тело в обменник и
получает `allow` с `VLAI_NO_TEXT`: ответ осмысленный, но это не проверка модели.

## Грабли

- **Без `REDIS_URL` контейнер вечно `unhealthy` при живом инспекторе.** Проба кладёт тело в
  обменник и берёт адрес только из окружения; блок `redis` в `inspector.conf` она не читает.
- **Первый старт долгий.** Пока веса качаются, подписки нет и контейнер не `healthy` — это не
  отказ.
- **В профилях булевы значения YAML 1.2.** Булевы только `true` и `false`, поэтому `on:` и
  `mode: off` значат ровно то, что написано.

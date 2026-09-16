FROM python:3.12-slim

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/vlai" \
      org.opencontainers.image.description="Placitum vlai inspector: severity of a vulnerability description, CPU build" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-vlai" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    VLAI_DEVICE=cpu \
    HOME=/var/lib/waf/vlai \
    HF_HOME=/var/lib/waf/vlai/hf \
    HF_HUB_DISABLE_TELEMETRY=1 \
    OMP_NUM_THREADS=4 \
    MKL_NUM_THREADS=4 \
    NATS_URL=nats://nats:4222 \
    WAF_VLAI_SUBJECT=waf.req.vlai \
    WAF_VLAI_NAME=vlai

WORKDIR /app

COPY deploy/entrypoint.sh /usr/local/bin/vlai-entry
COPY requirements.txt ./

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
        --extra-index-url https://pypi.org/simple \
        torch==2.14.0 \
 && pip install --no-cache-dir -r requirements.txt \
 && chmod +x /usr/local/bin/vlai-entry \
 && adduser --disabled-password --gecos "" --uid 10001 --no-create-home vlai \
 && mkdir -p /var/lib/waf/vlai \
 && chown -R vlai:vlai /var/lib/waf/vlai

COPY src ./src
COPY inspector.conf ./inspector.conf

USER vlai

VOLUME ["/var/lib/waf/vlai"]

HEALTHCHECK --interval=15s --timeout=8s --start-period=180s --retries=3 \
    CMD ["python", "/app/src/probe.py", "--quiet", "--timeout", "5000", "--deadline", "2000", \
         "--body", "{\"description\":\"vlai readiness check\"}", "--expect", "score"]

ENTRYPOINT ["vlai-entry"]
CMD ["inspect"]

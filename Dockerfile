FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/daygle

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app

# Unprivileged runtime user; all state lives in the /data volume.
RUN useradd --system --create-home --uid 10001 daygle \
    && mkdir -p /data \
    && chown daygle:daygle /data

USER daygle

ENV DATA_DIR=/data \
    WEB_PORT=8080 \
    HONEYPOT_PORT=22

EXPOSE 22 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

CMD ["python", "-m", "app"]

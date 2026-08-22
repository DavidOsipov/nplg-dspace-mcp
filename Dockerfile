FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

RUN groupadd --gid 10001 nplg \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/nplg --shell /usr/sbin/nologin nplg

WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN python -m pip install --require-hashes --no-deps --only-binary=:all: -r requirements.lock

COPY src ./src
COPY scripts/delete_render.py ./scripts/delete_render.py
COPY deploy/pdf-worker-slot-policy.json /etc/nplg/pdf-worker-slot-policy.json
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./

RUN chmod -R a=rX /app/src /app/scripts \
    && mkdir -p /data/cache \
    && chown -R 10001:10001 /data /home/nplg

USER 10001:10001
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"]

CMD ["python", "-m", "nplg_mcp"]

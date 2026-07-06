# ---- Stage 1: build the React frontend -------------------------------------
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Python runtime ------------------------------------------------
FROM python:3.12-slim

# The test engine shells out to the openssl CLI (monitor/path-validation).
# python:slim ships it; this guard fails the build early if a future base
# image drops it — in that case add `apt-get install -y openssl` here.
# (OCSP POST probes use the requests library, not the curl binary, so curl is
# intentionally NOT required at runtime.)
RUN openssl version

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY ocsp_tester/ ocsp_tester/
COPY backend/ backend/
COPY cli.py ./
COPY --from=frontend /build/dist frontend/dist

RUN useradd --create-home --uid 10001 ocspweb \
    && mkdir -p /data \
    && chown -R ocspweb:ocspweb /data /app
USER ocspweb

ENV OCSPWEB_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

# Single worker by default: run supervision and live-stream wakeups are
# per-process; streams still work across workers (DB-backed) if you raise this.
# --forwarded-allow-ips defaults to the loopback proxy only. Set
# OCSPWEB_FORWARDED_ALLOW_IPS to the reverse proxy's address/subnet (never '*',
# which trusts spoofable X-Forwarded-* from any client and defeats login
# rate-limiting and audit attribution).
CMD ["sh", "-c", "exec gunicorn backend.app.main:app -k uvicorn.workers.UvicornWorker -w ${GUNICORN_WORKERS:-1} -b 0.0.0.0:8000 --timeout 120 --graceful-timeout 30 --forwarded-allow-ips \"${OCSPWEB_FORWARDED_ALLOW_IPS:-127.0.0.1}\""]

# OCSP Testing Web

A browser-based version of the [OCSPTesting](https://github.com/jgoodloe/OCSPTesting)
tool: a professional internal engineering application for testing OCSP
responders, CRLs, certificate path validation and Federal PKI behavior.

The original `ocsp_tester` test engine is preserved intact (protocol, status,
security, performance, CRL, path-validation, IKEv2 and the OCSPMonitor
Federal PKI / DHS CA4 logic) and now runs behind a FastAPI backend with a
React UI, instead of Tkinter.

## Quick start (Docker)

```bash
git clone https://github.com/jgoodloe/ocspcrltesting
cd ocspcrltesting
docker compose up --build
# open http://localhost:8080/
```

That gives you the app behind nginx at the root path. For a subpath
deployment (`/ocsp/`), see [docs/DEPLOYMENT_NGINX.md](docs/DEPLOYMENT_NGINX.md).

From the browser you can:

- create a test run (upload issuer / known-good / known-revoked certificates,
  pick categories and request options),
- watch logs and results stream live (WebSocket with SSE fallback,
  reconnect-safe),
- drill into each result (responder ID, signature algorithm OID,
  thisUpdate/nextUpdate/producedAt, nonce echo, RFC references),
- export JSON/CSV, browse run history, and save reusable test profiles.

## Architecture

```
browser (React + TS SPA)
   │  REST + WebSocket/SSE   (all URLs relative to <base href>, subpath-safe)
   ▼
nginx  ── X-Forwarded-* / upgrade headers ──►  FastAPI (backend/app)
                                                │  api/       REST + streaming routers
                                                │  jobs.py    run supervisor
                                                │  storage.py run workspaces + retention
                                                │  SQLite (SQLAlchemy 2, PostgreSQL-ready)
                                                ▼
                                    worker subprocess (backend/app/worker)
                                      │  netguard: SSRF policy on every request
                                      │  executor: runs engine categories
                                      │  analysis: WARN/RFC enrichment
                                      ▼
                                    ocsp_tester/  (the original test engine)
```

Every test run executes in its **own subprocess**, so a hung responder or a
crashing OpenSSL invocation can never block the API; cancellation and
timeouts are process-group kills. The worker emits JSONL events which are
persisted (`run_events` table) and streamed; browsers can disconnect and
resume from any sequence number.

## Local development

Backend (Python 3.10+, OpenSSL on PATH):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements-dev.txt
uvicorn backend.app.main:app --reload --port 8000
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

Tests:

```bash
python -m pytest backend/tests
```

Headless CLI (no web stack needed):

```bash
python cli.py --ocsp-url http://ocsp.example.com --issuer issuer.pem \
    --good good.pem --categories protocol,status,crl --json-out results.json
```

## Configuration

Everything is environment-driven (`OCSPWEB_*`); see
[.env.example](.env.example). Highlights:

| variable | purpose |
|---|---|
| `OCSPWEB_BASE_PATH` | subpath deployment, e.g. `/ocsp` |
| `OCSPWEB_AUTH_PASSWORD` | enable HTTP Basic auth |
| `OCSPWEB_ALLOW_PRIVATE_TARGETS` | allow lab responders on private networks |
| `OCSPWEB_MAX_CONCURRENT_RUNS` | run parallelism |
| `OCSPWEB_RETENTION_DAYS` | uploaded-file retention |

## Documentation

- [docs/API.md](docs/API.md) — REST/WebSocket/SSE contract
- [docs/DEPLOYMENT_NGINX.md](docs/DEPLOYMENT_NGINX.md) — nginx root/subpath, systemd, gunicorn
- [docs/DEPLOYMENT_HOMELAB.md](docs/DEPLOYMENT_HOMELAB.md) — single compose file + Nginx Proxy Manager
- [docs/SECURITY.md](docs/SECURITY.md) — SSRF policy, auth, key handling
- [docs/PATH_VALIDATION_TESTS.md](docs/PATH_VALIDATION_TESTS.md) — engine path-validation test reference

## Known limitations

- IKEv2 tests are placeholders (as in the original tool) — they document what
  an IKEv2 harness would need to exercise and report SKIP.
- Request method / nonce overrides apply to status, CRL, path-validation and
  performance requests; transport tests (`tests_protocol`) and nonce
  compliance tests (`tests_security`) intentionally keep their own explicit
  request shapes, otherwise they would no longer test what they claim.
- Progress granularity is per category (the engine reports results in
  category batches); the results table still fills in as each category
  completes.
- A run's totals and latency summary are computed from engine-reported
  metrics; load-test latencies are included when the load test is enabled.
- Multi-worker gunicorn deployments work (streams are DB-backed), but a run's
  supervisor lives in the worker process that accepted the POST; keep
  `GUNICORN_WORKERS=1` unless you need more HTTP throughput.

# Deploying behind nginx

The application is designed to run behind a reverse proxy, at either the
domain root or a subpath. Both configurations are provided ready to use.

## What the app needs from the proxy

| header | why |
|---|---|
| `X-Forwarded-For` | client addresses in logs |
| `X-Forwarded-Proto` | correct scheme for generated URLs / docs |
| `X-Forwarded-Host` | correct host for generated URLs |
| `X-Forwarded-Prefix` | (subpath only, informational) the stripped prefix |
| `Upgrade` / `Connection` | WebSocket live stream |

`proxy_buffering off` and a long `proxy_read_timeout` are required for the
Server-Sent-Events fallback and WebSocket streams. The app also sends
`X-Accel-Buffering: no` on SSE responses.

Gunicorn/uvicorn is started with `--forwarded-allow-ips` so the forwarded
headers are honored; restrict that to your proxy's address when the proxy is
not on localhost/a private compose network.

## Root deployment — `https://ocsp.example.com/`

Use [`nginx/root.conf`](../nginx/root.conf). Leave `OCSPWEB_BASE_PATH` unset.

```bash
docker compose up --build     # nginx on :8080 proxying the app
```

For TLS, add a `listen 443 ssl;` server (or put this behind your existing
TLS-terminating frontend); nothing app-side changes because the scheme is
taken from `X-Forwarded-Proto`.

## Subpath deployment — `https://example.com/ocsp/`

1. Set the base path on the app:

   ```bash
   # .env
   OCSPWEB_BASE_PATH=/ocsp
   ```

2. Use [`nginx/subpath.conf`](../nginx/subpath.conf) (in `docker-compose.yml`,
   swap the mounted config file).

How it works — there are no hardcoded URLs in the browser bundle:

- nginx strips `/ocsp` (`proxy_pass http://app:8000/;` with trailing slash).
- The backend rewrites the SPA's `<base href="/">` to `<base href="/ocsp/">`
  at serve time; all asset URLs in the build are relative and resolve against
  that base.
- The frontend derives its router basename, API base (`/ocsp/api/...`) and
  WebSocket URL (`wss://host/ocsp/api/...`) from `document.baseURI` at
  runtime.
- FastAPI's `root_path` is set from `OCSPWEB_BASE_PATH`, so `/ocsp/api/docs`
  and the OpenAPI schema are correct too.

Any prefix works (`/tools/ocsp` etc.) — adjust both the nginx `location` and
`OCSPWEB_BASE_PATH` consistently.

## Production run command (no Docker)

```bash
gunicorn backend.app.main:app \
  -k uvicorn.workers.UvicornWorker \
  -w 1 \
  -b 127.0.0.1:8000 \
  --timeout 120 --graceful-timeout 30 \
  --forwarded-allow-ips 127.0.0.1
```

Plain uvicorn also works for small deployments:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --proxy-headers \
    --forwarded-allow-ips 127.0.0.1
```

Note on workers: live-stream reads are database-backed, so any worker can
serve any stream, but each run's supervisor (subprocess ownership, timeout,
cancellation escalation) lives in the worker that accepted the POST. One
worker is the simple, recommended configuration; raise `-w` only for HTTP
throughput and keep runs modest.

## systemd

A hardened unit with install instructions is provided at
[`deploy/ocsp-testing-web.service`](../deploy/ocsp-testing-web.service). Pair
it with one of the nginx configs above (proxying `127.0.0.1:8000`, replace
the `app:8000` upstream with `127.0.0.1:8000`).

## Checklist

- [ ] `client_max_body_size` ≥ `OCSPWEB_MAX_UPLOAD_BYTES`
- [ ] WebSocket upgrade headers present (live logs stop working without them;
      the UI falls back to SSE automatically, which needs `proxy_buffering off`)
- [ ] `OCSPWEB_AUTH_PASSWORD` set for anything reachable beyond your team
- [ ] `OCSPWEB_ALLOW_PRIVATE_TARGETS` only if the lab responders are private
- [ ] TLS terminated at nginx with `X-Forwarded-Proto $scheme`

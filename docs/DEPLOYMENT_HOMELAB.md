# Homelab deployment (single compose file + Nginx Proxy Manager)

For stacks where many apps live in one `docker-compose.yml` behind
[Nginx Proxy Manager](https://nginxproxymanager.com/) (NPM). Unlike apps such
as authentik, this tool can run as a deliberately **single container**: test
runs execute as subprocesses inside the container, so there is no redis/worker
sidecar to compose. The compose block below uses on-disk **SQLite** on a volume,
which is the simplest choice for a homelab. PostgreSQL is also supported (async
`asyncpg` driver and Alembic migrations are included, and the repo's own
`docker-compose.yml` uses it by default) — point `OCSPWEB_DATABASE_URL` at a
Postgres instance if you prefer it. Postgres has not yet been exercised by the
full CI test suite (issue #5), so validate against your target version before
relying on it in production.

## Compose block

```yaml
  # =======================================================
  # ocsp-testing
  # =======================================================

  ocsp-testing:
    # Prebuilt by CI (.github/workflows/build.yml) for amd64 and arm64. Pushes
    # to main publish `:latest` (and `:sha-<commit>`); feature branches publish
    # a preview image tagged with the branch name (the `claude/` session prefix
    # stripped), e.g. branch `claude/test-platform-enhancements-be455f` →
    # `ghcr.io/jgoodloe/ocspcrltesting:test-platform-enhancements-be455f`. Every
    # tag is multi-arch, so it pulls on both x86 servers and ARM homelab hosts.
    # If the GHCR package is private, either make it public (repo → Packages →
    # package settings) or `docker login ghcr.io` on the host. To build from
    # source instead, replace `image:` with
    # `build: https://github.com/jgoodloe/ocspcrltesting.git#main`.
    image: ghcr.io/jgoodloe/ocspcrltesting:latest
    container_name: ocsp-testing
    restart: unless-stopped
    # Inject the whole .env into the CONTAINER. This is required for auth: a
    # root .env is only used for ${VAR} substitution in this file — it is NOT
    # passed to the container unless a var is listed under environment: or
    # pulled in here. Without env_file the OCSPWEB_OIDC_* vars never reach the
    # app and the SSO button silently never appears. See docs/AUTH.md.
    env_file:
      - .env
    healthcheck:
      # curl is not in the image; the healthcheck is python-based
      test: ["CMD", "python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"]
      start_period: 15s
      interval: 30s
      retries: 5
      timeout: 5s
    environment:
      OCSPWEB_DATA_DIR: /data
      # Homelab: allow testing responders/CRLs on RFC1918 addresses.
      # Leave false if you only test public responders — see docs/SECURITY.md
      OCSPWEB_ALLOW_PRIVATE_TARGETS: ${OCSP_ALLOW_PRIVATE:-true}
      OCSPWEB_MAX_CONCURRENT_RUNS: ${OCSP_MAX_RUNS:-2}
      OCSPWEB_RETENTION_DAYS: ${OCSP_RETENTION_DAYS:-30}
      # Only needed for subpath serving (see below):
      # OCSPWEB_BASE_PATH: /ocsp
    volumes:
      - .ocsp-testing/data:/data
    # Host port only for first-run/direct access; NPM proxies internally.
    ports:
      - "9003:8000"
    networks:
      - nginx_proxy_manager_network
```

Put the auth/secret settings in a `.env` file next to the compose file (the
`env_file: [.env]` above loads them into the container):

```ini
# Multi-user auth (see docs/AUTH.md). Required for login to be enforced.
OCSPWEB_SESSION_SECRET=<openssl rand -hex 32>
OCSPWEB_BOOTSTRAP_ADMIN_PASSWORD=<something-strong>   # break-glass local admin
OCSPWEB_PUBLIC_BASE_URL=https://ocsp.example.com

# authentik / OIDC SSO (optional) — all three needed for the SSO button.
OCSPWEB_OIDC_ISSUER=https://auth.example.com/application/o/<app-slug>/
OCSPWEB_OIDC_CLIENT_ID=...
OCSPWEB_OIDC_CLIENT_SECRET=...
OCSPWEB_OIDC_SCOPES=openid email profile
OCSPWEB_OIDC_GROUP_CLAIM=groups
```

> **Gotcha:** editing `.env` and running `docker compose restart` does **not**
> reload it. Use `docker compose up -d --force-recreate ocsp-testing`. Verify
> with `docker compose exec ocsp-testing env | grep OIDC` or
> `curl -s https://<host>/api/auth/config` (expect `"oidc_enabled": true`).

`OCSPWEB_AUTH_PASSWORD` (the old shared HTTP Basic password) is superseded by the
multi-user model and no longer recommended. The full list of `OCSPWEB_*`
variables is in [`.env.example`](../.env.example); auth specifics, including
group → role mapping, are in [`docs/AUTH.md`](AUTH.md).

## Bind-mount permissions (the one gotcha)

The container runs as a non-root user, **uid 10001**. With a bind mount like
`.ocsp-testing/data`, create the directory first or the app cannot write its
SQLite database and run workspaces:

```bash
mkdir -p .ocsp-testing/data && sudo chown -R 10001:10001 .ocsp-testing/data
```

If you prefer a named volume (as in the repo's own `docker-compose.yml`),
this step is unnecessary — Docker chowns named volumes to the image's user
automatically.

## Nginx Proxy Manager — subdomain (recommended)

Add a proxy host, e.g. `ocsp.yourdomain.tld`:

- Scheme `http`, forward host `ocsp-testing`, forward port `8000`
- **Enable "Websockets Support"** — the live run log stream is a WebSocket;
  without the upgrade headers it silently falls back to SSE, which then also
  needs buffering disabled, so just enable the toggle.

Leave `OCSPWEB_BASE_PATH` unset. Nothing else is required.

## Nginx Proxy Manager — subpath

Possible but clunkier, because NPM's custom-location UI does not strip
prefixes. Set `OCSPWEB_BASE_PATH: /ocsp` on the container, then on the proxy
host add a custom location `/ocsp/` and paste this into its **Advanced** box
(this mirrors [`nginx/subpath.conf`](../nginx/subpath.conf)):

```nginx
proxy_pass http://ocsp-testing:8000/;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header X-Forwarded-Proto $scheme;
proxy_buffering off;
proxy_read_timeout 3600s;
```

The trailing slash on `proxy_pass` is what strips the `/ocsp` prefix. If NPM
fights you on this, the subdomain route is genuinely the better experience.

## Other notes

- `OCSP_ALLOW_PRIVATE=true` is the right call for a homelab where you test
  internal CAs/responders on 10.x/192.168.x — that is exactly the lab
  override it exists for. Cloud-metadata IPs stay blocked regardless.
- Uploads are capped at 5 MB by default; if you raise
  `OCSPWEB_MAX_UPLOAD_BYTES`, also bump `client_max_body_size` in the NPM
  proxy host's Advanced tab.
- No docker socket, no `user: root`, no internal network needed — the
  container makes outbound requests to your responders and that's it.

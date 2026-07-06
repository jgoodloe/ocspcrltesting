# Security notes

This tool makes outbound HTTP requests to user-supplied OCSP and CRL URLs and
accepts certificate uploads — both are attack surfaces that this design
addresses explicitly. It is intended for **trusted internal networks**; do
not expose it to the public internet without authentication and network
egress controls.

## SSRF protection

User-supplied URLs (OCSP responder, CRL overrides) and URLs *discovered
during testing* (AIA/OCSP, CA Issuers, CRL distribution points read from
certificates and responses) are all outbound request targets.

Enforcement happens in two layers:

1. **Submission time** (`backend/app/ssrf.py`): the OCSP/CRL URLs in a new
   run are validated before the run is accepted; violations return `403`.
2. **Request time** (`backend/app/worker/netguard.py`): inside the per-run
   worker process, `requests.Session.send` is patched so every `requests`-based
   outbound call the engine makes — including each redirect hop and every
   discovered URL — is re-validated, timeout-capped and size-capped.

The API server process also fetches one class of user-supplied URL directly:
the CA-library "fetch from URL" endpoint (`/api/ca-certs/fetch`). It has no
`requests` net-guard, so it uses `ssrf.guarded_fetch`, which validates the
initial URL **and every redirect hop** before opening a socket and caps the
response size.

Default policy (all configurable via environment, see `.env.example`):

- **Blocked**: loopback (`127/8`, `::1`, `localhost`), link-local
  (`169.254/16`, `fe80::/10`), RFC1918/ULA private space, cloud metadata
  addresses (`169.254.169.254` and friends), multicast/reserved space,
  non-HTTP(S) schemes (no `file:`, no FTP, no Unix sockets).
- **Redirects are not followed** unless `OCSPWEB_ALLOW_REDIRECTS=true`;
  when enabled, every hop is validated against the same policy.
- **Timeout ceiling** `OCSPWEB_MAX_REQUEST_TIMEOUT_SECONDS` applies no matter
  what a run requests.
- **Response size cap** `OCSPWEB_MAX_RESPONSE_BYTES` is enforced while
  streaming the body, not after.
- Every blocked request is **logged** with the target and the reason, both in
  the server log and in the run's log stream (`[NETGUARD] Blocked ...`).

`OCSPWEB_ALLOW_PRIVATE_TARGETS=true` permits private/loopback lab responders.
Cloud metadata addresses remain blocked even in this mode. You can extend the
blocklist with `OCSPWEB_EXTRA_BLOCKED_HOSTS`.

Note: `openssl ocsp`/`openssl` (and `curl`) subprocess calls made by the engine
(path-validation and Federal PKI helpers) go directly to the responder that
the run was already validated against; the primary URL guard has been applied
before any of those run. Because those calls do not go through `requests`, the
net-guard's per-hop re-validation and size cap do **not** apply to them.

### Known limitations

The URL guards are validate-then-connect. A residual gap a public-facing
operator should account for:

- **DNS rebinding / TOCTOU** — validation resolves the hostname, but the actual
  connection re-resolves it, so a rebinding DNS answer can bypass the IP checks.
  The `openssl`/`curl` engine calls are likewise not size-capped.

Keep `OCSPWEB_ALLOW_PRIVATE_TARGETS=false` and apply network egress controls
(allowlist the intended OCSP/CRL hosts) when the service is reachable beyond an
isolated lab.

## Authentication

Authentication is the multi-user model documented in [AUTH.md](AUTH.md): signed
session cookies (local login and/or OIDC/authentik SSO) plus per-user,
workspace-scoped, role-capped API bearer tokens. Enable it by setting
`OCSPWEB_SESSION_SECRET` and a bootstrap admin password (and/or OIDC). Passwords
are hashed with argon2id; API tokens are stored only as SHA-256 hashes. Session
cookies are `HttpOnly`, `Secure` (by default) and `SameSite=Lax`. Terminate TLS
in front of the app so cookies/tokens are never sent in clear.

With **no** auth configured the app runs open — a single anonymous global
administrator in a shared workspace — acceptable only on isolated lab networks.
This is a fail-open default: the shipped `docker-compose.yml` leaves
`OCSPWEB_SESSION_SECRET`/`OCSPWEB_BOOTSTRAP_ADMIN_PASSWORD` empty, so a plain
`docker compose up` is **unauthenticated** until you configure auth.

> The legacy shared-password HTTP Basic auth (`OCSPWEB_AUTH_PASSWORD`) is
> **no longer implemented** — setting it does not provide a Basic-auth login
> path. Use the session/OIDC/token model above.

## Uploaded certificates and private keys

- Uploads are stored in a per-run workspace (`$OCSPWEB_DATA_DIR/runs/<id>/uploads`),
  normalized to PEM, and never at a hardcoded path.
- The optional TLS client key is written with `0600` permissions, is **never
  parsed for display, never logged, never returned by any API** (run configs
  report only the original file name). The worker's log pipeline additionally
  redacts any line containing `PRIVATE KEY` as defense in depth.
- Files that fail PEM/DER parsing are rejected with a `400` before a run is
  created; upload size is capped by `OCSPWEB_MAX_UPLOAD_BYTES` (`413`).
- Workspaces are deleted when a run is deleted and swept automatically after
  `OCSPWEB_RETENTION_DAYS`.

## Output handling

- All user- and responder-controlled strings are returned as JSON and
  rendered as text nodes by the React frontend (no `dangerouslySetInnerHTML`),
  so responder-supplied data cannot inject markup.
- API errors use a uniform `{"detail": ...}` envelope; unhandled exceptions
  return a generic 500 without internals.

## CORS and proxy

- CORS headers are disabled by default (same-origin deployment through
  nginx). Set `OCSPWEB_CORS_ORIGINS` only if a separate origin must call the
  API; credentials mode is enabled for those origins only.
- The app trusts `X-Forwarded-*` only from addresses passed to
  `--forwarded-allow-ips` (see deployment docs). Note the shipped `Dockerfile`
  currently sets this to `*` (trusts forwarded headers from any client) — an
  open hardening item; restrict it to the reverse-proxy address/subnet.

## Execution isolation

- Each run executes in its own subprocess with its own process group; run
  cancellation/timeouts kill the whole group (including any `openssl`
  children). A wedged run cannot block the API server.
- Concurrency is capped by `OCSPWEB_MAX_CONCURRENT_RUNS` (`429` beyond it).
- The Docker image runs as a non-root user (`uid 10001`).

## Reporting

This is an internal tool; report issues via the repository issue tracker.

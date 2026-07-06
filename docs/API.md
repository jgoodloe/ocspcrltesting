# OCSP Testing Web — API Reference

All endpoints are rooted at the configurable base path (default `/`, e.g. `/ocsp`
behind a subpath reverse proxy). Paths below are relative to that base.

Authentication depends on how the deployment is configured — see
[AUTH.md](AUTH.md) for the full model:

- **Open mode** — with no auth configured the API runs as a single anonymous
  administrator in the shared `Default` workspace. Intended for isolated
  local/lab use only (see the safety note in the README).
- **Session login** — set `OCSPWEB_SESSION_SECRET` and
  `OCSPWEB_BOOTSTRAP_ADMIN_PASSWORD` to enable local login and signed session
  cookies.
- **OIDC (SSO)** — set `OCSPWEB_OIDC_ISSUER`/`_CLIENT_ID`/`_CLIENT_SECRET`.
- **API tokens** — mint per-user bearer tokens (workspace-scoped, role-capped)
  and send `Authorization: Bearer ocspt_...`. Browsers cannot set headers on a
  WebSocket handshake, so the stream endpoint also accepts a `token` query
  parameter.

```bash
curl -H "Authorization: Bearer ocspt_..." \
     "https://ocsp.example.com/api/test-runs?workspace_id=3"
```

> The legacy shared-password HTTP Basic auth (`OCSPWEB_AUTH_PASSWORD` /
> `OCSPWEB_AUTH_USERNAME`) has been superseded by the multi-user model and is
> **no longer implemented** — the app performs no Basic authentication. Use the
> session/OIDC/token auth above instead.

Content type is `application/json` unless noted. Errors use a consistent envelope:

```json
{ "detail": "human readable message" }
```

Validation errors from FastAPI may return the standard 422 structure.

---

## Health and metadata

### `GET /api/health`
Liveness/readiness probe. No auth required.

```json
{ "status": "ok", "database": "ok", "openssl": "3.0.13", "time": "2026-07-03T12:00:00Z" }
```

### `GET /api/version`

```json
{ "name": "ocsp-testing-web", "version": "1.0.0", "engine": "ocsp_tester" }
```

---

## Certificate inspection

### `POST /api/certificates/inspect`
`multipart/form-data` with a single field `file`. Accepts PEM or DER
certificates. Returns parsed metadata (used by the UI to preview uploads).

Response `200`:

```json
{
  "subject": "CN=Example Leaf,O=Example",
  "issuer": "CN=Example CA,O=Example",
  "serial_number": "0x0A1B2C",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2027-01-01T00:00:00Z",
  "key_algorithm": "RSA-2048",
  "signature_algorithm": "sha256WithRSAEncryption",
  "signature_algorithm_oid": "1.2.840.113549.1.1.11",
  "ski": "ab:cd:...",
  "aki": "12:34:...",
  "aia_ocsp_urls": ["http://ocsp.example.com"],
  "aia_ca_issuers": ["http://crl.example.com/ca.p7c"],
  "crl_distribution_points": ["http://crl.example.com/ca.crl"],
  "is_ca": false,
  "expired": false,
  "self_signed": false
}
```

Errors: `400` when the file is not a parseable PEM/DER certificate,
`413` when it exceeds `OCSPWEB_MAX_UPLOAD_BYTES`.

---

## Test runs

### `POST /api/test-runs`
Starts a test run. `multipart/form-data`:

| field | type | required | notes |
|---|---|---|---|
| `config` | JSON string | yes | see RunConfig below |
| `issuer_cert` | file | yes | PEM or DER |
| `good_cert` | file | no | known-good leaf |
| `revoked_cert` | file | no | known-revoked leaf |
| `unknown_ca_cert` | file | no | cert from a CA unknown to the responder |
| `trust_anchor` | file | no | root/intermediate chain (PEM, may contain multiple certs) |
| `client_cert` | file | no | TLS client certificate (PEM) |
| `client_key` | file | no | TLS client key (PEM). Never logged, never returned. |

**RunConfig JSON:**

```json
{
  "name": "optional label",
  "ocsp_url": "http://ocsp.example.com",
  "crl_urls": ["http://crl.example.com/ca.crl"],
  "request_method": "auto",          // "auto" | "get" | "post"
  "nonce_enabled": true,
  "nonce_length": 32,                 // 1..128, default 32 (RFC 9654)
  "latency_samples": 5,               // 1..100
  "enable_load_test": false,
  "load_concurrency": 5,              // 1..64
  "load_requests": 50,                // 1..2000
  "timeout_seconds": 10,              // per-request, 1..120
  "run_timeout_seconds": 900,         // whole run, 30..7200
  "max_age_hours": 24,
  "trust_anchor_type": "root",       // "root" | "intermediate"
  "require_explicit_policy": false,
  "inhibit_policy_mapping": false,
  "categories": {
    "protocol": true,
    "status": true,
    "crl": true,
    "path_validation": true,
    "ikev2": false,
    "federal": false,
    "performance": false,
    "security": true
  },
  "test_selection": {                 // fine-grained selection inside the enabled categories
    "mode": "all",                    // "all" | "global" | "custom"
    "tests": {}                       // custom mode: {category: [test name, ...]};
                                      // a category absent from the map runs all of its tests
  },
  "profile_id": null                  // optional provenance marker
}
```

With `mode: "global"` the server-wide selection (see
`/api/settings/test-selection`) is resolved when the run is created; with
`mode: "custom"` the `tests` map is used. The applied selection is recorded
on the run as `config.resolved_test_selection` (`null` = all tests ran).
Test names must match the catalog from `GET /api/test-catalog`.

`saved_certs` (optional) maps an upload slot (`issuer_cert`, `good_cert`,
`revoked_cert`, `unknown_ca_cert`, `trust_anchor`) to a saved CA library id
(see `/api/ca-certs`); the referenced certificate is used exactly as if it
had been uploaded. A slot may come from a file or the library, not both;
`issuer_cert` must come from one of the two. Client TLS material can never
come from the library.

Response `201`: a **RunSummary** (see below) with status `queued` or `running`.

Errors: `400` invalid config/certificate, `413` upload too large,
`422` malformed multipart, `403` when the OCSP/CRL URL is blocked by the
SSRF policy, `429` when `OCSPWEB_MAX_CONCURRENT_RUNS` runs are active.

### `GET /api/test-runs?limit=20&offset=0&status=completed`
Lists runs, newest first. Response:

```json
{ "items": [RunSummary, ...], "total": 42 }
```

**RunSummary:**

```json
{
  "id": "b7c9...",
  "name": "nightly lab check",
  "ocsp_url": "http://ocsp.example.com",
  "status": "running",   // queued|running|completed|failed|cancelled|timed_out
  "created_at": "...", "started_at": "...", "finished_at": null,
  "totals": { "pass": 10, "fail": 1, "warn": 2, "skip": 3, "error": 0, "total": 16 },
  "latency": { "median_ms": 42, "min_ms": 30, "max_ms": 95, "samples": 5 },
  "categories": ["protocol", "status", "crl"],
  "current_activity": "Running CRL tests",
  "error": null
}
```

### `GET /api/test-runs/{run_id}`
Single RunSummary plus the sanitized run config under `"config"` (uploaded
file names included; key material never included).

### `GET /api/test-runs/{run_id}/results`
Query params: `category`, `status` (comma-separated), `q` (search in
name/message). Response:

```json
{
  "items": [
    {
      "id": "uuid",
      "category": "Protocol",
      "name": "HTTP GET transport",
      "status": "PASS",              // PASS|FAIL|WARN|SKIP|ERROR
      "message": "GET accepted",
      "details": { ... },             // includes responder metadata, timestamps,
                                      // signature algorithm OID, nonce_echoed,
                                      // rfc_refs, warnings where applicable
      "started_at": "...", "ended_at": "...", "duration_ms": 123
    }
  ],
  "total": 16
}
```

`details.diagnostics` (when present) records what the test actually did,
for troubleshooting:

```json
{
  "http": [
    {
      "method": "POST", "url": "http://ocsp.example.com/",
      "status_code": 200, "reason": "OK", "duration_ms": 45,
      "request_bytes": 85, "request_body_b64": "...",       // ≤4 KiB bodies
      "response_bytes": 1712, "response_body_b64": "...",
      "response_content_type": "application/ocsp-response",
      "curl": "…reproduction command…",
      "started_at": "...", "ended_at": "..."
    }
  ],
  "commands": [
    {
      "command": "openssl ocsp -issuer ... -url ... -resp_text -noverify",
      "returncode": 0, "duration_ms": 120,
      "stdout_excerpt": "...", "stderr_excerpt": "...",
      "started_at": "...", "ended_at": "..."
    }
  ]
}
```

Each recorded exchange/command is also emitted as a `DEBUG` log line
(`[HTTP] …` / `[CMD] …`) in the run log.

### `GET /api/test-runs/{run_id}/logs?after_seq=0&limit=1000`
Persisted log lines (also replayed on stream reconnect):

```json
{ "items": [ { "seq": 1, "ts": "...", "level": "INFO", "message": "..." } ], "last_seq": 431 }
```

### `GET /api/test-runs/{run_id}/export/json`
Download; `Content-Disposition: attachment`. Full run report: summary,
config (sanitized), results, and log lines.

### `GET /api/test-runs/{run_id}/export/csv`
CSV of results: `id,category,name,status,message,duration_ms,started_at,ended_at,details`.

### `POST /api/test-runs/{run_id}/profile`
Saves the run's configuration as a reusable profile (works for finished
runs; uploaded certificates are not stored). Body:

```json
{ "name": "Nightly lab profile", "description": "optional" }
```

Response `201`: the created **Profile**. `409` when the name is taken,
`404` unknown run.

### `POST /api/test-runs/{run_id}/rerun`
Starts a **new** run reusing the run's configuration and its already-uploaded
certificates (copied from the original run's workspace) — no re-selecting
files. The original run and its results are kept intact; the new run records
`config.rerun_of` = original run id. Response `201`: the new RunSummary.
`404` unknown run, `409` when the original certificates are no longer
available (removed by retention cleanup), `403`/`429` as for `POST /test-runs`.

### `POST /api/test-runs/{run_id}/cancel`
Cancels a queued/running run. Response: updated RunSummary. `409` if already finished.

### `DELETE /api/test-runs/{run_id}`
Deletes the run record, results, logs and its upload workspace. `204`.

---

## Live stream

### `WS /api/test-runs/{run_id}/stream?after_seq=0`
WebSocket. Server pushes JSON events; on connect, events with `seq >
after_seq` are replayed from persistence, then live events follow. The same
event schema is used for SSE.

### `GET /api/test-runs/{run_id}/stream/sse` (`text/event-stream`)
SSE fallback. `Last-Event-ID` (or `?after_seq=`) resumes. Each SSE `id:` is
the event `seq`.

**Event envelope:**

```json
{ "seq": 17, "type": "log", "run_id": "...", "data": { ... } }
```

| type | data |
|---|---|
| `log` | `{ "ts", "level", "message" }` |
| `progress` | `{ "current_activity", "categories_done", "categories_total", "percent" }` |
| `result` | one result object (same shape as `/results` items) |
| `run_status` | RunSummary (sent on state transitions and as final event) |

A `run_status` event with a terminal `status` is always the last event.

---

## Profiles

Saved test configurations. Profiles never store certificate/key material —
only the run options and OCSP/CRL URLs; certificates are (re)uploaded per run.

### `GET /api/profiles`
`{ "items": [Profile, ...] }`

### `POST /api/profiles`

```json
{ "name": "Lab responder", "description": "optional", "config": RunConfig-without-profile_id }
```

Response `201` Profile:

```json
{ "id": 3, "name": "...", "description": "...", "config": { ... },
  "created_at": "...", "updated_at": "..." }
```

### `PUT /api/profiles/{profile_id}` — same body as POST, response Profile.
### `DELETE /api/profiles/{profile_id}` — `204`.

`409` on duplicate profile name.

### `POST /api/profiles/{profile_id}/share`
Body `{ "target_workspace_id": N }`. Copies the profile into another workspace.
The caller must be a **member or admin** (never merely a viewer) of the target
workspace. Response `201` with the new Profile. `400` when the target is the
source workspace, `403` when the caller lacks contributor rights in the target,
`404` unknown profile, `409` when a profile of that name already exists in the
target.

---

## Test catalog and global test selection

### `GET /api/test-catalog`
The individual tests each category can run — the vocabulary for
`test_selection` in run configs and the global selection setting:

```json
{
  "categories": [
    {
      "key": "protocol",
      "label": "OCSP protocol tests",
      "tests": [
        { "name": "HTTP GET transport",
          "description": "Responder accepts RFC 6960 base64 GET requests",
          "dynamic": false,
          "scope": "ocsp" }
      ]
    }
  ]
}
```

`dynamic: true` marks tests whose name is a stable prefix and which may emit
one result per input (e.g. `Fetch and parse CRL: <url>`). `scope` marks what
the test exercises: `ocsp`, `crl`, `crl+ocsp`, `path`, or `ikev2`.

### `GET /api/settings/test-selection`
The server-wide default selection applied to runs whose config uses
`test_selection.mode == "global"`:

```json
{ "tests": { "protocol": ["HTTP GET transport"] }, "updated_at": "..." }
```

`tests: null` means the global selection runs everything.

### `PUT /api/settings/test-selection`
Body `{ "tests": {category: [test name, ...]} | null }`. Category keys and
test names are validated against the catalog (`400` on unknown entries).
Response: the stored selection.

---

## Saved CA certificate library

Store commonly used root / issuing CA certificates once and reference them
in run configs via `saved_certs` instead of re-uploading files.

### `GET /api/ca-certs`
`{ "items": [CACert, ...] }` where CACert is
`{ id, name, subject, issuer, serial_number, fingerprint_sha256, not_before,
not_after, is_ca, expired, self_signed, source, source_url, created_at }`.

### `POST /api/ca-certs` — multipart upload
Fields: `file` (PEM, DER, PEM bundle, or PKCS#7 `.p7c`/`.p7b`), optional
`name` query param (applies when the file holds a single certificate).
Bundles create one entry per certificate; duplicates (by SHA-256
fingerprint) are skipped. Response `201`:
`{ "created": [CACert, ...], "skipped_duplicates": 0 }`.

### `POST /api/ca-certs/fetch`
Body `{ "url": "http://repo.fpki.gov/fcpca/fcpcag2.crt", "name": null }`.
The server downloads the certificate (SSRF policy applies, 2 MiB cap) and
imports it like an upload. The initial URL **and every redirect hop** are
re-validated against the policy before a connection is opened. `403` when
blocked by policy, `502` on fetch failure, `400` when the payload is not
certificate data.

### `GET /api/ca-certs/well-known`
Curated list of well-known Federal PKI CAs
(`{ key, name, url, description }`) for one-click import via `/fetch`.

### `GET /api/ca-certs/{id}`
Full record including the stored PEM: CACert plus `{ "pem": "-----BEGIN…" }`.
`404` unknown id (or not in this workspace).

### `GET /api/ca-certs/{id}/download`
The certificate as `application/x-pem-file` with a
`Content-Disposition: attachment` filename derived from its name. `404`
unknown id.

### `POST /api/ca-certs/{id}/share`
Body `{ "target_workspace_id": N }`. Copies the saved certificate into another
workspace. The caller must be a **member or admin** (never merely a viewer) of
the target workspace. Response `201`
`{ "created": [CACert, ...], "skipped_duplicates": 0 }` (the target already
having the certificate — by fingerprint — yields `created: []`,
`skipped_duplicates: 1`). `400` when the target is the source workspace, `403`
when the caller lacks contributor rights in the target, `404` unknown id.

### `PATCH /api/ca-certs/{id}`
Renames a saved certificate. Body `{ "name": "New name" }`. Response: the
updated CACert. `404` unknown id.

### `DELETE /api/ca-certs/{id}` — `204`.
Runs already created keep their materialized copy; profiles referencing the
deleted id fail run creation with a clear `400`.

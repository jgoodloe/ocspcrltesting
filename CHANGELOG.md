# Changelog

All notable changes to this project are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## Unreleased

### Project infrastructure

- Dependabot updates for pip, npm, Docker base images, and GitHub Actions (#41).
- CodeQL code scanning for Python and JavaScript/TypeScript (#42).
- GitHub Releases are now published automatically from the tag's CHANGELOG
  section on `v*` pushes, including the GHCR pull line (#44).
- Dependency-review gate on pull requests (#45).
- Vulnerability disclosure policy: private reporting instructions in
  `docs/SECURITY.md` plus a root `SECURITY.md` pointer (#46).
- Scheduled cleanup of stale GHCR branch-preview images, plus immediate
  cleanup when a branch is deleted (#47).
- Issue forms (bug / feature / security hardening) and a pull request
  template (#48).
- README status badges (#49).
- Weekly scheduled CI run to catch dependency and toolchain drift; scheduled
  runs never publish images (#50).

## v1.0.0 — Initial release

**OCSP/CRL Testing Web** is a self-hostable web application (with a companion
CLI) for testing and monitoring OCSP responders and CRL endpoints. It exercises
certificates and revocation infrastructure against RFC 6960 (OCSP), RFC 5280
(certificate/CRL profile and path validation), and U.S. Federal PKI / Federal
Bridge requirements, and reports what passed, what failed, and why.

### What it does

Point it at an OCSP responder URL (and optional CRL URLs), give it the
certificates to test, and it runs the selected suites:

- **OCSP protocol** — GET/POST transport, DER encoding, response structure,
  nonce handling, and hash-algorithm support.
- **Certificate status** — good / revoked / unknown / unauthorized responses.
- **CRL** — distribution-point discovery, fetch and parse, signature and
  freshness checks, and CRL-vs-OCSP consistency.
- **Path validation (RFC 5280)** — signature and name chaining, validity
  periods, basic constraints, key usage, path-length, and policy processing,
  with AIA-based chain discovery and PKCS#7 (`.p7c`) bundle handling.
- **Federal PKI / Federal Bridge** — policy mapping, delegated-responder EKU,
  and agency response handling.
- **Performance** — latency sampling and optional load testing.
- **Security & error handling** — response signature validation and
  unauthorized/malformed/`sigRequired` request handling.
- **IKEv2** — informational OCSP-in-IKEv2 checks.

Results stream live, one per test, with a pass / fail / warn / skip / error
status, the relevant RFC references, and per-test diagnostics (the HTTP
exchanges and commands that ran). Runs can be exported as JSON or CSV.

### Ways to use it

- **Web UI** — interactive runs, live progress, and run history.
- **REST API** — for automation and CI, authenticated with per-user bearer
  tokens (see `docs/API.md`).
- **CLI** (`cli.py`) — local or scripted runs.

### Multi-user

- Organize work into **workspaces** with **viewer / member / admin** roles;
  runs, profiles, and saved certificates are isolated per workspace.
- Sign in with **OIDC SSO** (e.g. authentik) or local username/password; OIDC
  groups can map to workspace roles.
- Mint **API tokens** scoped to a workspace and capped to a role.

### Certificates & profiles

- Keep a **saved CA library** (upload, fetch by URL, or import well-known
  Federal PKI CAs) and reference it in runs instead of re-uploading files.
- Inspect a saved certificate's details and v3 extensions — Subject Alternative
  Names, key usage, extended key usage, certificate policies, AIA, CRL
  distribution points, and key identifiers — download its PEM, or share it into
  another workspace.
- Save run configurations as reusable **profiles**, and share them across
  workspaces.

### Running it

- **Requirements:** Docker (recommended), or Python 3.12 + Node for a source
  build; the engine uses the `openssl` CLI. PostgreSQL is recommended for
  multi-user deployments; SQLite is fine for single-user or development.
- **Quick start:** `docker compose up` — see `README_WEB.md` and
  `docs/DEPLOYMENT_HOMELAB.md` / `docs/DEPLOYMENT_NGINX.md`.
- **Authentication:** configure auth before exposing the app on a network. With
  no auth configured it runs "open" (single anonymous admin) and will refuse to
  start unless you explicitly opt into that mode.
- **Reverse proxy:** serves cleanly behind a proxy, including under a subpath.
- **Outbound safety:** because it fetches user-supplied URLs, it enforces an
  SSRF policy by default — loopback, private, link-local, and cloud-metadata
  targets are blocked; a lab mode can relax this for internal testing.

### Documentation

- `README_WEB.md` — overview and setup
- `docs/API.md` — REST API reference
- `docs/AUTH.md` — authentication and workspaces
- `docs/DEPLOYMENT_HOMELAB.md`, `docs/DEPLOYMENT_NGINX.md` — deployment guides
- `docs/SECURITY.md` — security model

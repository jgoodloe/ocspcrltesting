# Changelog

All notable changes to this project are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## Unreleased

- The UI is now titled **OCSP CRL Testing** (sidebar, login, page title),
  and the footer version comes from the single backend constant.
- Releases now **fail if the version constant was not bumped** to match the
  tag, so the footer/API can never report a stale version again (v1.1.0 and
  v1.2.0 shipped reporting 1.0.0).

## v1.2.0 — Security hardening and supply-chain trust

### Fixed

- **Federal PKI responder detection** matched agency domains as URL
  substrings, so a hostname like `evildhs.gov.example.com` (or a `dhs.gov`
  path segment) was misclassified as a DHS responder. Detection now parses
  the URL hostname and requires an exact or subdomain match.

### Changed

- **Run ids are validated at the API boundary**: every `/api/test-runs/{id}`
  route (including streams, cancel, delete, and exports) now rejects
  malformed ids with a **422** before any handler code runs; well-formed but
  unknown ids still return 404. Run ids have always been server-generated
  UUIDs, so no valid client is affected.
- User-supplied values (URLs, profile names, run ids, worker-derived status)
  are CR/LF-escaped before logging, so crafted input cannot forge log lines.
- Dependency floors raised past all published 2025-26 advisories
  (authlib 1.6.12, starlette 1.3.1, python-multipart 0.0.31; pytest 9 for
  the dev suite).

### Supply chain & CI

- Published images now carry **SLSA provenance and an SPDX SBOM**, and
  `main`/tag images get a GitHub-signed attestation — verify with
  `gh attestation verify oci://ghcr.io/jgoodloe/ocspcrltesting:1.2.0 --owner jgoodloe`.
- Docker base images are digest-pinned and every GitHub Action is pinned to
  a commit SHA, with pinning enforced in CI from now on (zizmor).
- New scanners reporting to the Security tab: **Trivy** (image OS packages +
  IaC misconfigurations), **hadolint** (Dockerfile), **OpenSSF Scorecard**
  (repo posture), **zizmor** (workflow security), alongside CodeQL now on
  the `security-extended` suite.
- A daily **security digest** mirrors all open alerts into a single tracked
  issue; green Dependabot minor/patch updates **auto-merge** after CI.

## v1.1.0 — Runtime, dependency, and automation refresh

### Dependencies & runtimes

- Docker image now builds on **Python 3.14** (`python:3.14-slim`) and
  **Node 26** (`node:26-alpine`); CI tests the same runtimes.
- **cryptography 49**, SQLAlchemy/uvicorn/aiosqlite/asyncpg/requests and
  friends raised to current releases.
- Frontend: **React 19**, **react-router-dom 7**, **Vite 8**, and
  **TypeScript 7** — each verified end-to-end, including under a subpath
  (`/ocsp/`) deployment.

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

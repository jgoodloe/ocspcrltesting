# Changelog

All notable changes to this project are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## v1.0.0 — Initial release

Initial public release of **OCSP/CRL Testing Web** — a FastAPI + React
application (with a companion CLI) for validating OCSP responders and CRLs
against RFC 6960 / RFC 5280 and U.S. Federal PKI requirements, with multi-user
workspaces.

### Highlights

**Test engine**
- OCSP protocol, certificate status, CRL, RFC 5280 path validation, Federal
  Bridge PKI, performance, security/error-handling, and IKEv2 test categories.
- AIA/CRL chain discovery, PKCS#7 (`.p7c`) bundle handling, and per-test result
  streaming to the live Run page.

**Multi-user**
- Workspaces with viewer / member / admin roles; per-run, per-profile and
  per-certificate isolation.
- OIDC (authentik) SSO and local login with signed session cookies; OIDC
  group → role sync.
- Per-user API tokens — workspace-scoped and role-capped — for automation.

**Certificates & profiles**
- Saved CA certificate library (upload, fetch-by-URL, or well-known Federal PKI
  import).
- Reusable run profiles.
- View (with parsed v3 extensions: SAN, key usage, EKU, certificate policies,
  AIA, CRL distribution points, SKI/AKI), download, and share into other
  workspaces.

**Deployment**
- Docker / docker-compose and systemd; PostgreSQL or SQLite; reverse-proxy
  subpath aware.

### Security

This release incorporates a full security review and remediation:

- **SSRF** hardening — redirect re-validation on server-side fetches,
  DNS-rebinding defeated by pinning connections to a validated IP, a worker-side
  validating resolver covering the engine's subprocesses, and IPv4-mapped-IPv6
  normalization so metadata/loopback can't be evaded (#28, #29, #39).
- **Fail-closed by default** — the app refuses to start with no authentication
  configured unless an operator explicitly opts into open mode (#30).
- **API-token workspace-scope confinement** — a scoped token can no longer
  reach other workspaces by omitting a parameter (#32).
- **Dependency floors** raised past known CVEs (authlib, gunicorn,
  python-multipart, requests, cryptography, starlette) (#31).
- Authentication required on certificate inspection (#35); reverse-proxy header
  trust tightened (#34); the `curl` argument-injection surface and the external
  `curl` dependency removed in favor of the `requests` library (#36, #8).

### Notable fixes

- One-time database migration relaxes legacy global unique constraints to
  per-workspace composites, so the same CA/profile can live in multiple
  workspaces (uploads and sharing no longer fail).
- Path-validation issuer/subject name-chaining now reports an unambiguous
  verdict and surfaces both DNs (#24).
- OCSP `producedAt` freshness only warns past 18 hours (#40).
- Live results stream per test instead of per category (#1).
- Saved-certificate view: parsed v3 extensions and a compact, scrollable PEM
  (#25).
- Profile and saved-certificate sharing into member/admin workspaces (#26, #27).

### Verifying

116 backend tests pass; the frontend builds clean.

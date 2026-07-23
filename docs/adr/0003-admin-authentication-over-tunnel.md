# ADR-0003: Admin authentication over remote access paths

- **Status:** Accepted (contingent on ADR-0002 remaining tunnel-based)
- **Date:** 2026-07-23
- **Relates to:** ADR-0002

## Context

OmniTrust ILM's default administrator authentication is **mutual TLS**: the client
presents a certificate, the ingress validates it, and the client identity is passed to
the Kong API gateway via the `ssl-client-cert` header (`auth.header.certificate`). The
chart auto-registers an initial admin from a certificate (`registerAdmin.*`).

**Cloudflare terminates TLS at its edge and does not forward client certificates
through a tunnel** (mTLS-to-origin is an Enterprise API Shield feature). So under
ADR-0002 Option A, certificate-based admin login cannot work for remote users.

## Decision

When the remote path is the Cloudflare Tunnel:

1. **Enable the chart's internal Keycloak** (`global.keycloak.enabled=true`) so remote
   admins and users authenticate with **username/password or OIDC** over the tunnel.
2. **Put Cloudflare Access in front** of the public hostname as an outer authentication
   gate (allowed emails / IdP group), so two layers guard the internet-facing surface:
   Access (who may reach the app) then Keycloak (who may use it).
3. **Keep the platform-issued admin client certificate as LAN-only break-glass.** It is
   still generated at install; export and store it in the password manager for use over
   the cluster-internal / LAN path (e.g. `kubectl port-forward`) when Cloudflare or the
   tunnel is unavailable.

If ADR-0002 is later ratified as Option B (port forward) or C (hybrid), native mTLS
admin login is preserved on the direct path and internal Keycloak becomes optional.

## Consequences

- **Positive:** working remote login over the tunnel; defense in depth on the public
  surface; a documented break-glass path independent of Cloudflare.
- **Negative:** internal Keycloak adds a component to run and back up; the public
  hostname must also resolve **inside** the cluster (CoreDNS rewrite +
  `apiGateway.hostAliases.resolveInternalKeycloak=true`) so Keycloak redirect flows do
  not hairpin out through the tunnel.
- **Security note:** REST API clients cannot perform interactive Access logins — plan
  Access **service tokens** for automation.

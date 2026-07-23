# Architecture Decision Records

This directory records architecturally significant decisions for the OmniTrust ILM
deployment work (and future decisions for this repository). Each ADR captures the
context, the decision, and its consequences at the time it was made.

Format is lightweight [MADR](https://adr.github.io/madr/)-style. ADRs are immutable
once **Accepted** — to change a decision, add a new ADR that supersedes the old one
and update the old one's status to `Superseded by ADR-NNNN`.

## Status values

- **Proposed** — under discussion, not yet committed
- **Accepted** — decided and in effect
- **Superseded** — replaced by a later ADR (linked)
- **Deprecated** — no longer relevant

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-deploy-omnitrust-ilm-on-single-node-k3s.md) | Deploy OmniTrust ILM on single-node k3s | Accepted |
| [0002](0002-external-access-method.md) | External access method (tunnel vs port-forward vs hybrid) | Proposed |
| [0003](0003-admin-authentication-over-tunnel.md) | Admin authentication strategy over remote access paths | Accepted |
| [0004](0004-postgresql-via-cloudnativepg.md) | Provide PostgreSQL in-cluster via CloudNativePG | Accepted |
| [0005](0005-ingress-nginx-and-cert-manager.md) | Disable Traefik; use ingress-nginx + cert-manager | Accepted |

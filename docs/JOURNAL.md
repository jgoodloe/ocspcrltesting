# Project Journal

A running log of design sessions, decisions, and research for this repository.
Newest entries first. Architecturally significant decisions are captured as ADRs
under [`docs/adr/`](adr/); this journal records the narrative and links to them.

---

## 2026-07-23 — OmniTrust ILM on k3s deployment planning

**Branch:** `claude/omnitrust-k3s-cloudflared-4vfx9l`

### Goal
Plan how to integrate the [OmniTrust ILM](https://github.com/OmniTrustILM) identity
lifecycle management platform onto a **new, dedicated machine**, using **cloudflared
tunnels** for external access.

### What was produced
- `docs/OMNITRUST_K3S_CLOUDFLARED_PLAN.md` — full 9-phase deployment plan (machine prep →
  k3s → foundations → PostgreSQL → ILM chart → tunnel → Access → platform config → ops),
  with architecture diagram, security section, effort estimate (~1.5 days), and open
  questions.
- `docs/adr/` — ADR set established (see below).
- This journal.

### Research findings
- **OmniTrust ILM = the open-source core formerly known as CZERTAINLY** (3Key Company);
  OmniTrust (formerly ISS) acquired it and folded it into its "Trust Lifecycle
  Management" platform. MIT-licensed, connector-based microservices architecture.
- Official umbrella Helm chart: `oci://hub.omnitrustregistry.com/ilm-helm/ilm`.
  Prerequisites: Kubernetes 1.19+, Helm 3.8+, PostgreSQL 12+, PV provisioner,
  cert-manager, ingress controller. Default image tag observed: `2.18.0`.
- Key value keys: `global.hostName`, `global.database.*`, `global.keycloak.enabled`,
  `ingress.*`, `registerAdmin.*`, per-connector `*.enabled` toggles.

### Decisions recorded
- **ADR-0001** — deploy on single-node k3s (Accepted).
- **ADR-0002** — external access method: tunnel vs port-forward vs hybrid (**Proposed**;
  pending answers on CGNAT, third-party-in-path acceptability, and remote admin needs).
- **ADR-0003** — admin auth over the tunnel: internal Keycloak + Cloudflare Access, with
  mTLS client cert kept as LAN-only break-glass (Accepted, contingent on ADR-0002).
- **ADR-0004** — PostgreSQL in-cluster via CloudNativePG (Accepted).
- **ADR-0005** — disable Traefik; use ingress-nginx + cert-manager (Accepted).

### Discussion threads
- **Port forwarding vs tunnel.** User asked about NAT port forwarding as an alternative.
  Key insight: port forwarding preserves the platform's **native mTLS client-certificate
  admin login** (TLS end-to-end to ingress), which the Cloudflare tunnel breaks. Trade-off
  is exposing the public IP and owning WAF/DDoS, plus it fails under CGNAT. Captured three
  options (tunnel / port-forward / hybrid) with comparison diagrams; folded into ADR-0002.
- **Competitive landscape.** Since ILM is ex-CZERTAINLY, its competitors are the CLM /
  machine-identity market: Keyfactor Command (+ EJBCA), CyberArk Venafi, AppViewX,
  DigiCert Trust Lifecycle Manager, Sectigo, Entrust, GlobalSign, Smallstep; open-source
  alternatives OpenXPKI, Dogtag, step-ca, cert-manager; adjacent overlap with HashiCorp
  Vault and PQC/crypto-discovery tools (SandboxAQ/Cryptosense). OmniTrust differentiates on
  open-source + flat-rate ($99K/yr unlimited certs) pricing.

### Tie-in with this repo
This repository's OCSP/CRL testing engine can validate the revocation infrastructure
(OCSP responders, CRL DPs) of any CA that OmniTrust ILM manages — an independent
RFC 6960 / 5280 conformance check of the new PKI (Phase 7 of the plan).

### Open items
1. Registry access model for `hub.omnitrustregistry.com` (anonymous vs `imagePullSecrets`).
2. Final public hostname / domain (fix before install — `global.hostName`).
3. Backup target for CloudNativePG (NAS / S3-compatible).
4. Whether the REST API must be reachable externally (drives Access service-token design).
5. Pin chart version and image tag rather than floating on latest.
6. **Resolve ADR-0002** (access method) — the one still-open architectural decision.

# ADR-0005: Disable k3s Traefik; use ingress-nginx + cert-manager

- **Status:** Accepted
- **Date:** 2026-07-23

## Context

k3s ships **Traefik** as its default ingress controller. The ILM chart, however, defaults
to `ingress.class: nginx` and documents its client-certificate header behavior
(`ssl-client-cert`, used by mTLS admin auth per ADR-0003) against **ingress-nginx**. The
chart also **requires cert-manager** for its internal CA / inter-service certificates
(`ingress.certificate.source: internal`).

## Decision

1. Install k3s with `--disable traefik`.
2. Install **ingress-nginx** (class `nginx`) as `ClusterIP` under the tunnel model
   (nothing is exposed on the node; `cloudflared` reaches it in-cluster). Under a
   port-forward model (ADR-0002 Option B) it becomes a `LoadBalancer` via k3s ServiceLB.
3. Install **cert-manager** (with CRDs) for the platform's internal certificates. Under a
   port-forward model, add a Let's Encrypt `ClusterIssuer` for the public server cert.

## Consequences

- **Positive:** matches the chart's documented assumptions; mTLS header handling works as
  designed; cert-manager satisfies a hard chart prerequisite.
- **Negative:** we forgo k3s's zero-config Traefik and own two more components.
- **Related requirement:** the public hostname must resolve to the ingress **inside** the
  cluster (CoreDNS rewrite) to avoid hairpinning — see ADR-0003.

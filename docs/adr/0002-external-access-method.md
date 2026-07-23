# ADR-0002: External access method — Cloudflare Tunnel vs NAT port forwarding vs hybrid

- **Status:** Proposed (decision pending — see "Open questions")
- **Date:** 2026-07-23
- **Context source:** Access-method discussion; diagrams in the access-options comparison

## Context

The platform must be reachable from outside the local network. Three options were
evaluated. The decisive factors are **where TLS terminates**, **whether the platform's
native mutual-TLS (client-certificate) admin login survives the path**, and **what the
NAT firewall must expose**.

| | A — Cloudflare Tunnel | B — NAT port forward | C — Hybrid |
|---|---|---|---|
| Inbound firewall ports | none | 443 (+80) | none, or 443 allowlisted |
| Where TLS terminates | Cloudflare edge | your ingress | edge (users) / ingress (admin) |
| Native mTLS admin login | broken | works | works on admin path |
| Third party sees traffic | yes (Cloudflare) | no | users yes / admin no |
| Works behind CGNAT | yes | no | tunnel path only |
| WAF / DDoS | Cloudflare | you own it | mixed |
| Extra auth gate | Cloudflare Access | mTLS at ingress | both |
| Public TLS cert | not needed (internal) | Let's Encrypt | needed for admin path |

## Decision

**Proposed default: Option A (Cloudflare Tunnel).** The user originally requested
`cloudflared` tunnels, and the tunnel exposes **no inbound ports**, works behind CGNAT,
and brings Cloudflare Access + WAF. The main cost — that mTLS client-cert admin login
does not survive the tunnel — is addressed by ADR-0003.

**Not yet ratified.** The user raised NAT port forwarding (Option B) as an alternative
because it preserves the platform's native mTLS admin auth end-to-end. Final selection
depends on the open questions below.

## Consequences

- **If A (tunnel):** requires internal Keycloak for login (ADR-0003); Cloudflare sees
  decrypted traffic at its edge — relevant because this is PKI infrastructure that may
  handle key material; API automation needs Cloudflare Access service tokens.
- **If B (port forward):** preserves native mTLS admin auth; needs a public/static IP
  (fails under CGNAT), a Let's Encrypt server cert via cert-manager, and makes us our own
  WAF/DDoS layer; mitigate by requiring client certs at the ingress and/or IP allowlisting.
- **If C (hybrid):** best security fit but the most moving parts.

## Open questions (resolve before ratifying)

1. Is the machine behind **CGNAT** or does it have a public IP? (CGNAT eliminates B.)
2. Is exposing the public IP acceptable for **PKI infrastructure**, or is "no third party
   in the data path" a hard requirement? (Pushes toward B or C.)
3. Do administrators need certificate-based login **remotely**, or is LAN/VPN acceptable
   for that path? (LAN-only admin makes A workable; remote mTLS pushes toward B/C.)

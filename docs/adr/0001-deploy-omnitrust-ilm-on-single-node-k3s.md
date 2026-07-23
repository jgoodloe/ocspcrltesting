# ADR-0001: Deploy OmniTrust ILM on single-node k3s

- **Status:** Accepted
- **Date:** 2026-07-23
- **Context source:** Deployment planning session; see `docs/OMNITRUST_K3S_CLOUDFLARED_PLAN.md`

## Context

We need to stand up the [OmniTrust ILM](https://github.com/OmniTrustILM) identity
lifecycle management platform (the open-source core formerly known as CZERTAINLY) on a
**brand-new, dedicated machine** in the environment. OmniTrust ILM is a microservices
stack (Java core, Kong API gateway, RabbitMQ, optional internal Keycloak, connector
services) distributed as an official umbrella Helm chart at
`oci://hub.omnitrustregistry.com/ilm-helm/ilm`, whose prerequisites are Kubernetes
1.19+, Helm 3.8+, PostgreSQL 12+, a PV provisioner, cert-manager, and an ingress
controller.

The workload is homelab/single-purpose scale for a first iteration, not a
multi-tenant fleet.

## Decision

Run the platform on a **single-node k3s cluster** on the new machine, rather than a
full multi-node Kubernetes distribution or plain Docker Compose.

- k3s satisfies every chart prerequisite (built-in `local-path` PV provisioner, standard
  Kubernetes API) with a single-binary install and low overhead.
- The chart is Helm-native, so Kubernetes is the path of least resistance; Compose would
  mean re-authoring the whole deployment.
- Single node keeps the first iteration simple. HA (`global.replicaCount`, StatefulSet
  workloads, multi-node) is explicitly deferred, not designed out.

## Consequences

- **Positive:** minimal install footprint; official chart used as-is; clear upgrade path
  to HA later; reproducible via version-controlled values.
- **Negative / risks:** single node is a single point of failure — backups (see ADR-0004)
  and a documented restore runbook are mandatory before go-live. Sizing must be adequate
  (≥ 4 vCPU / 16 GB RAM / 100 GB SSD) because Kong + RabbitMQ + Keycloak + core +
  PostgreSQL all share one host.

# ADR-0004: Provide PostgreSQL in-cluster via CloudNativePG

- **Status:** Accepted
- **Date:** 2026-07-23

## Context

The ILM chart requires an **external PostgreSQL 12+** (`global.database.*`); it does not
bundle a database. On a single-node deployment we still want managed-database features:
backups, point-in-time recovery, and low-friction major-version upgrades.

## Decision

Run PostgreSQL **in-cluster using the CloudNativePG (CNPG) operator** — a `Cluster` with
one instance and a PVC on k3s's `local-path` StorageClass, in a dedicated `databases`
namespace. Credentials live in a Kubernetes Secret; the chart points at the CNPG service
(`ilm-pg-rw.databases.svc.cluster.local:5432`).

Fallback if CNPG proves too heavy for the single-node scale: the Bitnami `postgresql`
Helm chart.

## Consequences

- **Positive:** declarative backups (`Backup`/`ScheduledBackup`, optional
  `barmanObjectStore` to off-box storage), WAL archiving for PITR, and managed major
  upgrades — valuable given the single-node SPOF from ADR-0001.
- **Negative:** the operator is one more component to understand and keep current.
- **Action item:** the **backup target (NAS / S3-compatible bucket) must be chosen before
  go-live**; on-box-only backups do not protect against machine loss.

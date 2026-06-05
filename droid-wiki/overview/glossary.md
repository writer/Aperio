# Glossary

This page defines the terms that show up across the API, UI, Prisma schema, and workers.

## Tenant

A tenant is an `Organization` row in `packages/db/prisma/schema.prisma`. Every integration, finding, SIEM destination, audit log, and agent record is scoped to one tenant.

## Connector

A connector is a SaaS provider definition in `packages/shared/src/connectors.ts`. It describes the provider name, credential fields, read scopes, remediation scopes, and detection checks.

## Integration

An integration is a stored connection in `packages/db/prisma/schema.prisma` as `IntegrationConnection`. It represents one tenant binding to one external account, such as a GitHub org or 1Password account domain.

## Read-only mode

`READ_ONLY` is the default `IntegrationMode` for connectors. The UI still ingests findings, but the remediation endpoints in `apps/api/src/routes/remediations.ts` refuse write actions.

## Remediation mode

`REMEDIATION` means the integration stores enough privileges to perform write actions. The scope list comes from `scopesForMode` in `packages/shared/src/connectors.ts`.

## Finding

A finding is a `SecurityFinding` row in `packages/db/prisma/schema.prisma`. Findings have a severity, risk score, remediation steps, evidence JSON, and a status such as `OPEN` or `RESOLVED`.

## Dedupe key

The dedupe key is the SHA-256 hash built in `workers/ingestion-worker.ts`. It keeps repeated observations of the same rule and target from creating duplicate finding rows.

## Disabled check

Each integration stores `disabledChecks`. The ingestion worker skips rule evaluation for those check keys.

## SIEM destination

A SIEM destination is a configured outbound sink in `SiemDestination`. The catalog lives in `packages/shared/src/siem.ts`, and the API lives in `apps/api/src/routes/siem.ts`.

## SIEM delivery

A SIEM delivery is one durable outbox row in `SiemDelivery`. `workers/siem-dispatcher.ts` retries failed rows and eventually marks them `DEAD_LETTER`.

## Canonical envelope

The canonical envelope is the payload shape built in `workers/siem-dispatcher.ts`, such as `aperio.finding.v1`. It standardizes what leaves the system regardless of the target SIEM.

## Agent

An agent is a registered actor in the A2A model. `packages/shared/src/a2a.ts` defines the schemas, `packages/db/prisma/schema.prisma` stores the data, and `apps/api/src/routes/agents.ts` plus `apps/mcp/src/server.ts` expose it.

## Agent task

An `AgentTask` is a unit of work for a registered agent. Tasks can be queued, assigned, started, completed, or blocked on approval.

## Agent proposal

An `AgentProposal` is a proposed action, often tied to a finding or task. The proposal can be approved or rejected through `apps/api/src/routes/agents.ts`.

## AAD

AAD means additional authenticated data. `packages/security/src/crypto.ts` binds ciphertext to tenant- and record-specific context so a token encrypted for one record cannot be replayed against another.

For the full data model, go to [Data models](../reference/data-models.md). For the shared schemas, go to [Shared](../packages/shared.md).

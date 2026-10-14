# HoneyForge MVP Specification

## Purpose and boundary

HoneyForge is a defensive honeypot platform for laboratory systems and infrastructure whose owner has authorized monitoring. It must provide both a reproducible single-machine demonstration and a distributed topology with the Control Center separated from Traps in a DMZ. High-interaction execution, third-party CDN routing, process masquerading, and use outside authorized infrastructure are out of scope.

The attached work plan is the source of scope: items marked Must define the MVP unless this specification explicitly resolves a contradiction. Bonus work starts only after the MVP acceptance gate passes.

## Required vertical scenario

An interaction with either the Low or Medium Trap becomes a normalized Security Event, is durably buffered by the Agent during an outage, is delivered over authenticated TLS, is stored in PostgreSQL exactly once despite retries, and appears in the authenticated UI through the recoverable realtime feed.

The Low Trap exposes static SSH, HTTP, and MySQL banner services. The Medium Trap exposes interactive fake-SSH and fake-HTTP services. Emulators implement only fixed behavior over a fictitious filesystem and never execute attacker input in a host shell, subprocess, Docker socket, or host filesystem.

## Domain model

The canonical terms and definitions live in [`../GLOSSARY.md`](../GLOSSARY.md). Code, API schemas, documentation, and the database use those names.

The MVP has six domain tables:

- `trap_profiles`
- `traps`
- `security_events`
- `attack_sessions`
- `operators`
- `audit_entries`

Honeytoken storage is introduced only with the Bonus feature. Traps and used profiles are archived rather than deleted. Events, sessions, and audit entries are immutable until retention cleanup. Security data is retained for 30 days and audit data for 365 days by default; both periods are configurable.

One connection forms one Attack Session for SSH and other connection-oriented protocols. HTTP requests from the same source to the same Trap belong to one Attack Session until 15 minutes of inactivity.

## Identity and authentication

The MVP has one seeded Operator and no registration, RBAC, or user-management UI. Login creates an eight-hour JWT session in a `Secure`, `HttpOnly`, `SameSite=Strict` cookie. WebSocket authentication uses the same cookie, and state-changing requests validate their origin.

An Operator pre-creates a Trap and issues a hashed, single-use Enrollment Token valid for ten minutes. The Agent exchanges it for a unique Trap Secret, of which the Control Center stores only a hash. Rotation permits a five-minute overlap; revocation has immediate effect. Agent secrets are mounted as protected files and are not built into images or exposed in process arguments. TLS is mandatory and certificate verification cannot be disabled. mTLS remains Bonus.

## Trap lifecycle and profiles

Trap Status is one of `provisioning`, `online`, `degraded`, `offline`, or `revoked`. Agents send health and profile checks every 30 seconds; absence for 90 seconds makes a Trap offline. These intervals are configurable.

A Trap Profile is versioned and contains an interaction level plus service definitions with protocol, internal port, and banner or emulator settings. It excludes deployment addresses and secrets. An Agent atomically applies an assigned version to new connections while existing connections finish on the old version. Invalid configuration or occupied ports leave the last good version active and put the Trap into `degraded`. Profile updates use version/ETag conflict detection.

## Event contract and delivery

MVP event types are `connection_opened`, `authentication_attempt`, `command_entered`, `http_request`, and `connection_closed`. Agent health and configuration errors are operational data rather than Security Events.

Every event includes an event UUID, schema version, Trap UUID, Attack Session UUID, event type, UTC `observed_at`, Control Center `received_at`, source address and port, target service and port, and a type-specific payload. Stable ordering uses `(received_at, UUID)` because Agent clocks are not authoritative.

Delivery is at least once. The Agent uses a SQLite WAL FIFO queue and retains each event until acknowledged as durably stored. Batches contain at most 500 events or 1 MiB. The API acknowledges individual UUIDs and explains rejections; permanently invalid records move to local quarantine. The default queue limit is 100,000 events or 256 MiB. At capacity, the oldest records are dropped and the data loss is logged locally and reported after connectivity returns.

## API and realtime

Operator endpoints live under `/api/v1`. Authenticated Agent endpoints are exposed externally under the Nginx-masked `/assets/v2` namespace without using a third-party CDN. Masking is not authentication.

Event queries filter by Trap, Attack Session, event type, source IP, and UTC time range and use cursor pagination. Telemetry ingestion is an API application module and commits normalized events in one database transaction. PostgreSQL `LISTEN/NOTIFY` publishes only committed event UUIDs; listeners load full rows and broadcast them through authenticated WebSockets. Reconnecting clients recover missed records through REST before resuming the live stream.

API documentation is enabled only in development. Login, mutation, enrollment, revocation, and export actions are audited; ordinary reads are not.

## User interface

The UI remains vanilla HTML, CSS, and JavaScript with four views: login, dashboard, Trap Profiles, and Security Events. It supports Trap status, profile CRUD and assignment, REST-backed event filters, automatic WebSocket reconnection, and gap recovery. Credentials and commands captured by Traps are visible only to authenticated Operators and are documented as sensitive data.

## Network and runtime safety

The demo uses a generated local CA trusted by Agents. Distributed installations use operator-provided certificates or a public CA. Nginx trusts forwarded client addresses only from configured internal proxies and enforces request-size and connection-rate limits. Emulators also limit concurrent clients, input sizes, and idle time.

The Agent runs unprivileged as `honeyforge-agent`. Containers use read-only filesystems where feasible, dropped capabilities, resource limits, dedicated writable volumes, and separated management networks. Services emit structured JSON logs without credentials, Trap Secrets, enrollment tokens, or JWTs. `/health` reports process liveness and `/ready` verifies mandatory dependencies; metrics are Bonus.

## Deployment and demo

`make demo` is the idempotent single entry point: it creates local configuration and certificates when absent, builds images, starts PostgreSQL, API/UI/Nginx and both Traps, applies migrations, and seeds demo records. Re-running it preserves data. Local Python is not required.

The supported demo environment is Linux on x86-64 or arm64 with Docker Engine and Compose v2. External ports are Control Center `8443`; Low SSH/HTTP/MySQL `2222`, `8080`, and `33060`; Medium SSH/HTTP `2223` and `8081`.

The Control Center and Trap compose definitions can also be deployed on separate hosts without changing service images or the domain model. Published production data is not yet supported, so the scaffold's initial migration may be replaced by the canonical schema.

## Testing and acceptance

The repository must contain unit tests for domain behavior, PostgreSQL integration tests for API and persistence, and an automated end-to-end smoke test covering attack, buffer/delivery, database persistence, and WebSocket presentation. A demo attack script produces deterministic SSH, HTTP, and MySQL interactions without attacking external systems.

The MVP is accepted only when a clean environment passes image build, migrations, unit/integration/end-to-end tests, `make demo`, and the documented manual scenario. Required evidence includes an accurate README, architecture and database diagrams, API/profile/deployment/masking documentation, demo script and walkthrough, working UI screenshots, presentation, and a test report. Documentation must describe observed behavior rather than planned behavior.

After that gate, Bonus work is considered in this order: beacon jitter, CSV export, dashboard charts, then honeytokens. GeoIP, maps, orchestration, STIX, mTLS, high-interaction execution, and Prometheus metrics remain later options.

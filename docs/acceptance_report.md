# HoneyForge MVP acceptance report

This is the repeatable acceptance gate for Issue #16. Run it from the repository
root on Linux x86-64 or arm64 with Docker Engine and Compose v2.

```bash
make demo
make demo-attack
make demo-smoke
python3 -m pytest -q
```

`make demo` is idempotent: it preserves `.env`, the local CA, PostgreSQL data,
Trap credentials, and existing seeded records. It only fills missing secrets and
creates the two named demo Trap Profiles/Traps. `make demo-attack` talks exclusively
to `127.0.0.1` and the documented local ports. `make demo-smoke` stops the
API/Nginx briefly, proves the Agent SQLite queue grows during the outage,
restores the stack, waits for those exact UUIDs to leave SQLite, verifies each
exactly once through PostgreSQL-backed REST catch-up, authenticates a
WebSocket, and asserts that the newly committed UUID is broadcast. The UI is
then visible at
`https://localhost:8443/events.html`; the WebSocket is served at `/ws`.

Evidence collected for the MVP gate:

| Gate | Evidence |
| --- | --- |
| Unit and UI behavior | `tests/` (including browser-backed UI tests when Chromium is installed) |
| PostgreSQL integration | `tests/test_postgres_schema.py`, `tests/test_realtime_events.py`, `TEST_DATABASE_URL=... pytest` |
| Clean deployment | `make demo` + Compose healthchecks |
| Attack and buffering | `make demo-attack`, Agent SQLite queue, `make demo-smoke` |
| REST catch-up and realtime UI | `/api/v1/security-events`, `/ws`, `center/web/events.html` |
| Operator visibility | HTTPS login, dashboard, Security Events and Trap Profiles pages |
| Documentation/package | `docs/architecture.md`, `docs/database.md`, `docs/deployment.md`, `docs/presentation.md`, `docs/screenshots/login.png` and `dashboard.png` |

## Observed run

The acceptance run was performed on 2026-10-15 in `/home/egor/HoneyForge` on
Linux x86-64 with Docker Compose v2 and Docker Engine. `make demo` built the
API, Collector, Web, Low Agent and Medium Agent images; PostgreSQL became
healthy, Alembic migrations completed, and both Agents reported running.
`make demo-attack` returned SSH banners, HTTP `200`/`404` responses and the
MySQL `5.7.42-MySQL` greeting. `make demo-smoke` returned:

```json
{"readiness":"ready","accepted_events":1,"buffered_delivery":true,"rest_catch_up":true,"operator_ui":true,"websocket":true}
```

The buffer portion stopped API/Nginx, observed `pending_events` increase in the
Low Agent SQLite WAL, restarted the Control Center, and then observed those
Security Event UUIDs leave SQLite and appear exactly once through REST. The
final current-commit run against the dedicated PostgreSQL database was `105
passed` with no skips. A dependency-only local run was also `66 passed, 39
skipped`; those skips are the PostgreSQL/browser fixtures exercised by the
full acceptance run.

`docs/screenshots/login.png` is captured from the running HTTPS endpoint and
`docs/screenshots/dashboard.png` is captured from the running HTTPS dashboard
with headless Chrome after Operator login and shows both seeded Traps online.
The browser UI tests in `tests/test_security_events_ui.py`
exercise persisted Security Event rendering and realtime gap recovery.

The Bonus backlog remains out of scope until this gate is green.

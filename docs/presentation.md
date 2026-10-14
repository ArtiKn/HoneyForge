# HoneyForge MVP presentation

## 1. What the judge sees

1. Open `https://localhost:8443/login.html` and sign in with the generated
   Operator credentials from `.env`.
2. Show the live fleet dashboard and the two seeded Trap Profiles.
3. Run `make demo-attack` in a second terminal.
4. Open Security Events: the SSH, HTTP and MySQL interactions arrive through the
   masked TLS endpoint and appear in the persisted Security Event stream.
5. Refresh the page to demonstrate REST catch-up, then leave it open to show the
   WebSocket updates.

## 2. The 90-second story

HoneyForge separates the Control Plane from the DMZ Trap fleet. Agents run
unprivileged, buffer Security Events locally during outages, and deliver them over a
verified TLS connection whose `/assets/v2/init` route is reverse-proxied by Nginx.
The API commits a Security Event and PostgreSQL publishes only its UUID; the
Operator UI recovers the full Security Event through REST and then follows live
WebSocket updates.

## 3. Ports

| Surface | Local port |
| --- | ---: |
| Control Center HTTPS | 8443 |
| Low SSH / HTTP / MySQL | 2222 / 8080 / 33060 |
| Medium SSH / HTTP | 2223 / 8081 |

Use `docs/demo_attack.md` for the longer scenario and `docs/acceptance_report.md`
for the reproducible gate.

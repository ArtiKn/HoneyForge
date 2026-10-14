# HoneyForge

Canonical language for the HoneyForge honeypot management and telemetry domain.

## Language

**Control Center**:
The central system that configures Traps, receives their telemetry, stores Security Events, and presents them to operators.
_Avoid_: Center, central server, management server

**Trap**:
A deployed honeypot instance that exposes deceptive services and observes interactions with them.
_Avoid_: Honeypot instance, decoy, Agent

**Trap Profile**:
A reusable configuration describing the deceptive services and behavior assigned to a Trap.
_Avoid_: Profile, config, honeypot profile

**Agent**:
The process that runs a Trap, records observed activity, buffers telemetry, and communicates with the Control Center.
_Avoid_: Trap, honeypot

**Security Event**:
A normalized record of one security-relevant observation made by a Trap.
_Avoid_: Event, log entry, telemetry event

**Attack Session**:
A bounded sequence of related Security Events observed by one Trap: one connection for connection-oriented protocols, or same-source HTTP activity separated by no more than 15 minutes of inactivity.
_Avoid_: Session, user session, connection

**Operator**:
An authenticated person who configures and monitors HoneyForge through the Control Center.
_Avoid_: User, admin

**Enrollment Token**:
A short-lived, single-use credential that authorizes an Agent to enroll one pre-created Trap.
_Avoid_: Registration key, API key, Trap Secret

**Trap Secret**:
The long-lived credential issued during enrollment that authenticates one Trap to the Control Center.
_Avoid_: Enrollment Token, shared secret, API key

**Trap Status**:
The Control Center's current lifecycle assessment of a Trap: `provisioning`, `online`, `degraded`, `offline`, or `revoked`.
_Avoid_: Agent status, health flag

**Agent Health Report**:
Operational telemetry describing an Agent's liveness, active profile version, buffer state, and configuration errors; it is not attacker activity and therefore is not a Security Event.
_Avoid_: Security Event, heartbeat event

# Deliver Security Events at least once

Agents assign every Security Event a UUID and retain it until the Control Center acknowledges durable storage. Retries may deliver an event more than once, so the Control Center deduplicates by UUID; this adds idempotency machinery in exchange for surviving temporary network and service failures without losing observations.

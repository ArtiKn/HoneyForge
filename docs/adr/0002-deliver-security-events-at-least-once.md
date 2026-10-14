# Deliver Security Events at least once

Agents assign every Security Event a UUID and retain it until the Control Center acknowledges durable storage. Retries may deliver an event more than once, so the Control Center deduplicates by UUID; this adds idempotency machinery in exchange for surviving temporary network and service failures without losing observations.

The Agent bounds this durable buffer by record count and byte volume. At capacity it evicts the oldest records, persists a Buffer Loss Report until the Control Center acknowledges that operational report, and logs the loss locally. Records that the Control Center permanently rejects become Quarantined Event Records: they remain available for local diagnosis but no longer block FIFO delivery of valid Security Events.

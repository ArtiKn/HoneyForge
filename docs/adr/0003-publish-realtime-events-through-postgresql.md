# Publish realtime events through PostgreSQL

Committed Security Events are published to WebSocket clients through PostgreSQL `LISTEN/NOTIFY`, even though the original work plan inconsistently labels that mechanism as Bonus while requiring realtime UI as Must. A notification carries only the event UUID; each listener loads the durable record before broadcasting it. After reconnecting, a client catches up through the cursor-paginated REST API before resuming the WebSocket stream, so realtime display does not pretend that WebSocket delivery is reliable storage.

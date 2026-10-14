# Keep telemetry ingestion inside the API

For the MVP, the collector remains an application module invoked by the masked telemetry endpoint instead of being deployed as a separate service. Ingestion is validation plus one database transaction, so splitting it would require a durable inter-service queue and another failure boundary without a demonstrated workload that justifies them; PostgreSQL notifications still decouple committed events from WebSocket delivery.

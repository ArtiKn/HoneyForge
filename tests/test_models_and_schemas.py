from uuid import uuid4

from center.api.models import AttackSession, Base, SecurityEvent, Trap, TrapProfile
from center.api.schemas.telemetry import TelemetryBatch
from center.collector.ingest import ingest
from center.collector.normalizer import normalize


def test_all_documented_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == {
        "trap_profiles",
        "traps",
        "security_events",
        "attack_sessions",
        "operators",
        "audit_entries",
    }
    assert SecurityEvent and Trap and TrapProfile and AttackSession


def test_empty_batch_contract() -> None:
    batch = TelemetryBatch(events=[])
    assert batch.model_dump() == {"events": []}
    assert ingest(batch.events) == 0


def test_security_event_contract_uses_canonical_identifiers_and_fields() -> None:
    batch = TelemetryBatch.model_validate(
        {
            "events": [
                {
                    "id": str(uuid4()),
                    "schema_version": 1,
                    "trap_id": str(uuid4()),
                    "attack_session_id": str(uuid4()),
                    "event_type": "connection_opened",
                    "observed_at": "2026-10-12T12:00:00Z",
                    "source_ip": "1.2.3.4",
                    "source_port": 1234,
                    "target_service": "ssh",
                    "target_port": 22,
                    "payload": {},
                }
            ]
        }
    )
    assert batch.events[0].event_type == "connection_opened"
    normalized = normalize(batch.events[0])
    assert "received_at" in normalized


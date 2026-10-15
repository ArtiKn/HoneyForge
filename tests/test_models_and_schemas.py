from uuid import uuid4

import pytest
from pydantic import ValidationError

from center.api.models import AttackSession, Base, SecurityEvent, Trap, TrapProfile
from center.api.config import Settings
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


def test_retention_defaults_keep_security_for_30_days_and_audit_for_365() -> None:
    settings = Settings()

    assert settings.security_data_retention_days == 30
    assert settings.audit_entry_retention_days == 365
    assert settings.retention_sweep_interval_seconds == 86_400


def test_empty_batch_contract() -> None:
    batch = TelemetryBatch(events=[])
    assert batch.model_dump() == {"events": []}
    assert ingest(batch.events) == 0


def test_batch_contract_rejects_more_than_500_events() -> None:
    event = {
        "id": str(uuid4()),
        "schema_version": 1,
        "trap_id": str(uuid4()),
        "attack_session_id": str(uuid4()),
        "event_type": "connection_opened",
        "observed_at": "2026-10-12T12:00:00Z",
        "source_ip": "192.0.2.1",
        "source_port": 1234,
        "target_service": "ssh",
        "target_port": 22,
        "payload": {"banner": "SSH-2.0-test"},
    }
    with pytest.raises(ValidationError):
        TelemetryBatch.model_validate({"events": [event] * 501})


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
                    "payload": {"banner": "SSH-2.0-OpenSSH_8.9p1"},
                }
            ]
        }
    )
    assert batch.events[0].event_type == "connection_opened"
    normalized = normalize(batch.events[0])
    assert "received_at" in normalized


@pytest.mark.parametrize(
    ("schema_version", "observed_at", "payload"),
    [
        (3, "2026-10-12T12:00:00Z", {"banner": "SSH-2.0-test"}),
        (1, "2026-10-12T12:00:00", {"banner": "SSH-2.0-test"}),
        (1, "2026-10-12T12:00:00Z", {}),
    ],
)
def test_connection_event_rejects_unknown_schema_naive_time_or_untyped_payload(
    schema_version: int, observed_at: str, payload: dict
) -> None:
    with pytest.raises(ValidationError):
        TelemetryBatch.model_validate(
            {
                "events": [
                    {
                        "id": str(uuid4()),
                        "schema_version": schema_version,
                        "trap_id": str(uuid4()),
                        "attack_session_id": str(uuid4()),
                        "event_type": "connection_opened",
                        "observed_at": observed_at,
                        "source_ip": "192.0.2.1",
                        "source_port": 1234,
                        "target_service": "ssh",
                        "target_port": 22,
                        "payload": payload,
                    }
                ]
            }
        )


@pytest.mark.parametrize(
    ("source_port", "target_service"), [(None, "ssh"), (1234, None)]
)
def test_connection_event_requires_source_and_target_context(
    source_port: int | None, target_service: str | None
) -> None:
    with pytest.raises(ValidationError):
        TelemetryBatch.model_validate(
            {
                "events": [
                    {
                        "id": str(uuid4()),
                        "schema_version": 1,
                        "trap_id": str(uuid4()),
                        "attack_session_id": str(uuid4()),
                        "event_type": "connection_opened",
                        "observed_at": "2026-10-12T12:00:00Z",
                        "source_ip": "192.0.2.1",
                        "source_port": source_port,
                        "target_service": target_service,
                        "target_port": 22,
                        "payload": {"banner": "SSH-2.0-test"},
                    }
                ]
            }
        )


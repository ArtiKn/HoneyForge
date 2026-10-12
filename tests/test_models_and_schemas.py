from center.api.models import Base, Event, Honeypot, Profile
from center.api.schemas.telemetry import TelemetryBatch
from center.collector.ingest import ingest


def test_all_documented_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == {
        "profiles",
        "honeypots",
        "events",
        "sessions",
        "honeytokens",
        "operators",
        "audit",
    }
    assert Event and Honeypot and Profile


def test_empty_batch_contract() -> None:
    batch = TelemetryBatch(events=[])
    assert batch.model_dump() == {"events": []}
    assert ingest(batch.events) == 0


def test_agent_event_contract_accepts_documented_identifiers_and_unix_time() -> None:
    batch = TelemetryBatch.model_validate(
        {
            "events": [
                {
                    "ts": 1,
                    "honeypot_id": "h1",
                    "src_ip": "1.2.3.4",
                    "src_port": 1234,
                    "dst_port": 22,
                    "proto": "tcp",
                    "action": "connect",
                    "creds": None,
                    "cmd": None,
                    "raw": "",
                }
            ]
        }
    )
    assert batch.events[0].honeypot_id == "h1"


"""IoC export of Security Events as CSV (FR-C7).

The center exposes the investigation filters of the Security Events view as a
CSV download: the same filtering, the same ordering, plus a Trap name column and
payload fields flattened for spreadsheet triage. Only CSV is produced; no STIX
bundle is part of the contract.
"""

import csv
import io
from uuid import uuid4

import pytest
import httpx

from center.api.security_event_csv import CSV_COLUMNS

pytestmark = pytest.mark.asyncio


async def register_trap(client, name: str = "export-edge") -> tuple[dict, str]:
    profile = await client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": f"{name} profile",
            "interaction_level": "low",
            "services": [{"protocol": "ssh", "internal_port": 22}],
        },
    )
    assert profile.status_code == 201, profile.text
    created = await client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": name, "trap_profile_id": profile.json()["id"]},
    )
    assert created.status_code == 201, created.text
    trap = created.json()
    enrolled = await client.post(
        "/assets/v2/enroll", json={"enrollment_token": trap["enrollment_token"]}
    )
    assert enrolled.status_code == 200, enrolled.text
    return trap, enrolled.json()["trap_secret"]


async def publish_events(client, trap: dict, secret: str) -> list[dict]:
    attack_session_id = str(uuid4())
    events = [
        {
            "id": str(uuid4()),
            "schema_version": 1,
            "trap_id": trap["id"],
            "attack_session_id": attack_session_id,
            "event_type": "connection_opened",
            "observed_at": "2026-10-14T12:00:00Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"banner": "SSH-2.0-OpenSSH_8.9p1"},
        },
        {
            "id": str(uuid4()),
            "schema_version": 1,
            "trap_id": trap["id"],
            "attack_session_id": attack_session_id,
            "event_type": "authentication_attempt",
            "observed_at": "2026-10-14T12:00:05Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"username": "root", "password": "=cmd|' /C calc'!A0", "accepted": False},
        },
        {
            "id": str(uuid4()),
            "schema_version": 1,
            "trap_id": trap["id"],
            "attack_session_id": attack_session_id,
            "event_type": "connection_closed",
            "observed_at": "2026-10-14T12:00:09Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"bytes_sent": 128},
        },
    ]
    delivered = await client.post(
        "/assets/v2/init",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/javascript",
        },
        json={"events": events},
    )
    assert delivered.status_code == 200, delivered.text
    assert set(delivered.json()["accepted"]) == {event["id"] for event in events}
    return events


def parse_csv(document: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(document, newline=""))
    return list(reader.fieldnames or []), list(reader)


async def test_export_returns_filtered_events_as_csv_attachment(
    operator_client,
) -> None:
    trap, secret = await register_trap(operator_client)
    await publish_events(operator_client, trap, secret)

    response = await operator_client.get("/api/v1/security-events/export.csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "honeyforge-ioc-" in disposition and disposition.endswith('.csv"')

    header, rows = parse_csv(response.text)
    assert header == list(CSV_COLUMNS)
    # One batch shares one received_at, so the tie-break is by id; the export
    # carries the same columns and the same set as the investigation view.
    assert {row["event_type"] for row in rows} == {
        "connection_opened",
        "authentication_attempt",
        "connection_closed",
    }
    assert {row["trap_name"] for row in rows} == {"export-edge"}
    opened = next(row for row in rows if row["event_type"] == "connection_opened")
    assert opened["payload"] == '{"banner":"SSH-2.0-OpenSSH_8.9p1"}'
    assert opened["source_ip"] == "192.0.2.44"
    assert opened["source_port"] == "54321"
    assert opened["target_service"] == "ssh"
    assert opened["received_at"].endswith("Z")


async def test_export_honours_every_investigation_filter(operator_client) -> None:
    trap, secret = await register_trap(operator_client, name="filtered-edge")
    await publish_events(operator_client, trap, secret)
    other, other_secret = await register_trap(operator_client, name="other-edge")
    await publish_events(operator_client, other, other_secret)

    by_trap = await operator_client.get(
        "/api/v1/security-events/export.csv", params={"trap_id": trap["id"]}
    )
    assert by_trap.status_code == 200
    _, rows = parse_csv(by_trap.text)
    assert len(rows) == 3
    assert {row["trap_id"] for row in rows} == {trap["id"]}

    by_type = await operator_client.get(
        "/api/v1/security-events/export.csv",
        params={"trap_id": trap["id"], "event_type": "authentication_attempt"},
    )
    _, rows = parse_csv(by_type.text)
    assert [row["event_type"] for row in rows] == ["authentication_attempt"]
    assert rows[0]["username"] == "root"
    assert rows[0]["accepted"] == "false"

    by_source = await operator_client.get(
        "/api/v1/security-events/export.csv",
        params={"trap_id": trap["id"], "source_ip": " 192.0.2.44 "},
    )
    assert len(parse_csv(by_source.text)[1]) == 3
    other_source = await operator_client.get(
        "/api/v1/security-events/export.csv",
        params={"trap_id": trap["id"], "source_ip": "192.0.2.99"},
    )
    assert parse_csv(other_source.text)[1] == []

    period = await operator_client.get(
        "/api/v1/security-events/export.csv",
        params={
            "trap_id": trap["id"],
            "received_from": "2020-01-01T00:00:00Z",
            "received_to": "2020-01-02T00:00:00Z",
        },
    )
    assert parse_csv(period.text)[1] == []


async def test_export_defuses_spreadsheet_formulas_and_truncates_to_limit(
    operator_client,
) -> None:
    trap, secret = await register_trap(operator_client, name="ioc-edge")
    events = await publish_events(operator_client, trap, secret)
    formula_attempt = {
        "id": str(uuid4()),
        "schema_version": 1,
        "trap_id": trap["id"],
        "attack_session_id": events[0]["attack_session_id"],
        "event_type": "authentication_attempt",
        "observed_at": "2026-10-14T12:00:20Z",
        "source_ip": "192.0.2.44",
        "source_port": 54321,
        "target_service": "ssh",
        "target_port": 22,
        "payload": {"username": "=HYPERLINK(\"http://evil\")", "password": "x", "accepted": True},
    }
    delivered = await operator_client.post(
        "/assets/v2/init",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/javascript",
        },
        json={"events": [formula_attempt]},
    )
    assert delivered.status_code == 200, delivered.text

    # A later batch proves the newest-first order of a capped export.
    newest = await publish_events(operator_client, trap, secret)
    response = await operator_client.get(
        "/api/v1/security-events/export.csv", params={"trap_id": trap["id"], "limit": 3}
    )
    _, rows = parse_csv(response.text)
    assert len(rows) == 3
    assert {row["event_id"] for row in rows} == {event["id"] for event in newest}

    _, limited = parse_csv(
        (
            await operator_client.get(
                "/api/v1/security-events/export.csv", params={"trap_id": trap["id"]}
            )
        ).text
    )
    attack = next(
        row for row in limited if row["event_id"] == formula_attempt["id"]
    )
    # The attacker-supplied login must not execute when the CSV is opened.
    assert attack["username"] == '\'=HYPERLINK("http://evil")'
    assert attack["accepted"] == "true"

    attempt = next(row for row in limited if row["username"] == "root")
    assert attempt["username"] == "root"
    # Credentials stay inside the raw payload column instead of dedicated cells.
    assert "password" not in CSV_COLUMNS
    assert '"password":"Backup"' not in attempt["payload"]
    assert attempt["payload"].startswith("{")


async def test_export_rejects_invalid_filters_and_requires_an_operator(
    postgres_application, viewer_client
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=postgres_application), base_url="https://test"
    ) as anonymous:
        assert (
            await anonymous.get("/api/v1/security-events/export.csv")
        ).status_code == 401

    for params in (
        {"source_ip": "192.0.2.20:54321"},
        {"received_from": "2026-10-15T12:00:00"},
        {
            "received_from": "2026-10-16T00:00:00Z",
            "received_to": "2026-10-15T00:00:00Z",
        },
        {"limit": 50_001},
        {"trap_id": "not-a-uuid"},
    ):
        response = await viewer_client.get(
            "/api/v1/security-events/export.csv", params=params
        )
        assert response.status_code == 422, params

    # A read-only Operator may share an investigation outside the center.
    assert (await viewer_client.get("/api/v1/security-events/export.csv")).status_code == 200
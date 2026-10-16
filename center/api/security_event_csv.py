"""IoC export of Security Events as CSV (FR-C7).

The center exports CSV only; no STIX bundle is produced. Columns are flattened
from the event envelope and the payload so the file can be triaged in a
spreadsheet, and the raw payload JSON is kept in the last column for analysts
who need the untouched record.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from center.api.models import SecurityEvent

CSV_COLUMNS: tuple[str, ...] = (
    "event_id",
    "received_at",
    "observed_at",
    "trap_name",
    "trap_id",
    "attack_session_id",
    "event_type",
    "source_ip",
    "source_port",
    "target_service",
    "target_port",
    "username",
    "accepted",
    "command",
    "cwd",
    "http_method",
    "http_path",
    "query",
    "database",
    "succeeded",
    "bytes_received",
    "sha256",
    "payload",
)

# Payload keys promoted to their own column; everything else stays in `payload`.
_PROMOTED_KEYS: tuple[str, ...] = (
    "username",
    "accepted",
    "command",
    "cwd",
    "method",
    "path",
    "query",
    "database",
    "succeeded",
    "bytes_received",
    "sha256",
)

_COLUMN_ALIASES: dict[str, str] = {"method": "http_method", "path": "http_path"}

# Spreadsheets execute cells that start with these characters as formulas, and
# attacker-controlled values (commands, logins) are part of every export.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _defuse(value: str) -> str:
    """Keep attacker-controlled text inert when the CSV is opened in Excel."""

    return f"'{value}" if value.startswith(_FORMULA_PREFIXES) else value


def _timestamp(value: datetime | None) -> str:
    if value is None:
        return ""
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def event_row(event: SecurityEvent, trap_name: str) -> dict[str, str]:
    """Flatten one Security Event into the export row contract."""

    payload: dict[str, Any] = event.payload or {}
    row = {
        "event_id": str(event.id),
        "received_at": _timestamp(event.received_at),
        "observed_at": _timestamp(event.observed_at),
        "trap_name": trap_name,
        "trap_id": str(event.trap_id),
        "attack_session_id": str(event.attack_session_id),
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "source_port": _scalar(event.source_port),
        "target_service": event.target_service or "",
        "target_port": _scalar(event.target_port),
        "payload": json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ),
    }
    for key in _PROMOTED_KEYS:
        column = _COLUMN_ALIASES.get(key, key)
        row[column] = _defuse(_scalar(payload.get(key)))
    return row


def render_security_event_csv(
    rows: Iterable[tuple[SecurityEvent, str]],
) -> str:
    """Render Security Events as an RFC 4180 CSV document (CRLF line endings)."""

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(CSV_COLUMNS),
        lineterminator="\r\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    for event, trap_name in rows:
        writer.writerow(event_row(event, trap_name))
    return buffer.getvalue()
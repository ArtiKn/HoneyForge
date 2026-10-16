"""Bounded MySQL wire emulation with fictitious, read-only data."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime
from typing import Any

from agent.low.honeyforge_low import _LowTcpService
from honeyforge_common.telemetry import captured_text


def length_encoded(value: str | bytes) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    if len(raw) < 251:
        return bytes([len(raw)]) + raw
    return b"\xfc" + len(raw).to_bytes(2, "little") + raw


class FakeDatabase:
    """Each connection owns its selected database; no SQL reaches a real engine."""
    def __init__(self) -> None:
        self.database = "app"

    def query(self, sql: str) -> tuple[list[str], list[tuple[str, ...]]]:
        text = sql.strip().rstrip(";").strip()
        normalized = re.sub(r"\s+", " ", text).upper()
        if normalized.startswith("SET ") or normalized in ("BEGIN", "COMMIT", "ROLLBACK"):
            return [], []
        match = re.fullmatch(r"USE\s+`?([A-Za-z_][A-Za-z0-9_]*)`?", text, re.I)
        if match:
            if match[1] not in ("app", "information_schema"):
                raise ValueError("Unknown database")
            self.database = match[1]
            return [], []
        if normalized in ("SELECT 1", "SELECT 1 AS ONE"):
            return ["1"], [("1",)]
        if normalized == "SELECT VERSION()":
            return ["VERSION()"], [("8.0.36",)]
        if normalized == "SELECT DATABASE()":
            return ["DATABASE()"], [(self.database,)]
        if normalized == "SELECT @@VERSION_COMMENT LIMIT 1":
            return ["@@version_comment"], [("MySQL Community Server - GPL",)]
        if normalized == "SHOW DATABASES":
            return ["Database"], [("app",), ("information_schema",)]
        if normalized == "SHOW TABLES" and self.database == "app":
            return ["Tables_in_app"], [("users",), ("settings",)]
        if normalized in ("DESCRIBE USERS", "DESC USERS") and self.database == "app":
            return ["Field", "Type", "Null", "Key", "Default", "Extra"], [
                ("id", "int", "NO", "PRI", "", ""),
                ("username", "varchar(64)", "YES", "", "", ""),
                ("email", "varchar(128)", "YES", "", "", ""),
            ]
        match = re.fullmatch(r"SELECT (\*|[A-Z_, `]+) FROM `?(USERS|SETTINGS)`?(?: LIMIT (\d{1,3}))?", normalized)
        if match and self.database == "app":
            if match[2] == "USERS":
                columns, rows = ["id", "username", "email"], [("1", "admin", "admin@example.test"), ("2", "backup", "backup@example.test")]
            else:
                columns, rows = ["name", "value"], [("environment", "production"), ("backup_path", "/var/backups/app")]
            selected = columns if match[1] == "*" else [v.strip().strip("`").lower() for v in match[1].split(",")]
            if any(v not in columns for v in selected):
                raise ValueError("Unknown column")
            rows = [tuple(row[columns.index(v)] for v in selected) for row in rows]
            return selected, rows[:int(match[3])] if match[3] else rows
        raise ValueError("Unsupported query")


class MediumMySqlService(_LowTcpService):
    protocol = "mysql"

    def __init__(self, *, banner: str | None = None, accepted_credentials: list[dict] | None = None,
                 capture_commands: bool = True, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.mysql_banner = banner or "8.0.36"
        self.accepted_credentials = accepted_credentials or []
        self.capture_commands = capture_commands

    def banner(self) -> str:
        return self.mysql_banner

    def _event(self, **kwargs: Any) -> dict:
        event = super()._event(**kwargs)
        if kwargs["event_type"] in ("database_query", "authentication_attempt"):
            event["schema_version"] = 2
        return event

    @staticmethod
    def native_response(password: str, nonce: bytes) -> bytes:
        if not password:
            return b""
        stage1 = hashlib.sha1(password.encode()).digest()
        stage2 = hashlib.sha1(stage1).digest()
        scramble = hashlib.sha1(nonce + stage2).digest()
        return bytes(a ^ b for a, b in zip(stage1, scramble))

    def accepted(self, username: str, response: bytes, nonce: bytes) -> bool:
        credentials = [c for c in self.accepted_credentials if c.get("service") in (None, "mysql")]
        return not credentials or any(
            c["username"] == username and hmac.compare_digest(response, self.native_response(c["password"], nonce))
            for c in credentials
        )

    async def _read_packet(self, reader: asyncio.StreamReader, sequence: int) -> bytes:
        header = await asyncio.wait_for(reader.readexactly(4), self.idle_timeout_seconds)
        length = int.from_bytes(header[:3], "little")
        if header[3] != sequence or length > self.max_input_bytes:
            raise ConnectionError("Invalid MySQL packet")
        return await asyncio.wait_for(reader.readexactly(length), self.idle_timeout_seconds)

    @staticmethod
    def _error(message: str) -> bytes:
        return b"\xff" + (1064).to_bytes(2, "little") + b"#42000" + message.encode()[:256]

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, **context: Any) -> int:
        sent = 0
        async def send(payloads: list[bytes], sequence: int = 1) -> None:
            nonlocal sent
            await self.exchange_timing.wait()
            for payload in payloads:
                packet = len(payload).to_bytes(3, "little") + bytes([sequence % 256]) + payload
                writer.write(packet)
                sent += len(packet)
                sequence += 1
            await writer.drain()

        def emit(kind: str, payload: dict) -> None:
            self.queue.enqueue(self._event(**context, event_type=kind,
                observed_at=datetime.now(UTC).isoformat(), payload=payload))

        nonce = secrets.token_bytes(20)
        capabilities = 1 | 4 | 8 | 512 | 8192 | 32768 | 131072 | 524288
        handshake = (b"\x0a" + self.mysql_banner.encode() + b"\x00" + secrets.randbits(32).to_bytes(4, "little")
                     + nonce[:8] + b"\x00" + (capabilities & 65535).to_bytes(2, "little")
                     + b"\x21\x02\x00" + (capabilities >> 16).to_bytes(2, "little")
                     + b"\x15" + b"\x00" * 10 + nonce[8:] + b"\x00mysql_native_password\x00")
        await send([handshake], 0)
        auth = await self._read_packet(reader, 1)
        if len(auth) < 33:
            return sent
        client_flags = int.from_bytes(auth[:4], "little")
        # TLS is not advertised; native auth responses fit the one-byte length encoding.
        if client_flags & 2048:
            await send([self._error("Unsupported authentication mode")], 2)
            return sent
        username_end = auth.find(b"\x00", 32)
        if username_end < 0 or username_end - 32 > 256:
            return sent
        username = auth[32:username_end].decode("utf-8", errors="replace")
        offset = username_end + 1
        if offset >= len(auth) or not client_flags & 32768:
            return sent
        length = auth[offset]
        offset += 1
        if length > 20 or offset + length > len(auth):
            return sent
        response = auth[offset:offset + length]
        offset += length
        accepted = self.accepted(username, response, nonce)
        emit("authentication_attempt", {
            "username": captured_text(username, enabled=self.capture_credentials, max_bytes=self.max_payload_bytes, max_chars=256, required=True),
            "password": "<challenge-response>" if self.capture_credentials and self.max_payload_bytes > 0 else "<redacted>",
            "accepted": accepted, "auth_scheme": "mysql_native_password",
            "auth_response": captured_text(response.hex(), enabled=self.capture_credentials, max_bytes=self.max_payload_bytes, max_chars=128),
            "auth_challenge": captured_text(nonce.hex(), enabled=self.capture_credentials, max_bytes=self.max_payload_bytes, max_chars=128),
        })
        if not accepted:
            await send([b"\xff\x15\x04#28000Access denied"], 2)
            return sent
        database = FakeDatabase()
        if client_flags & 8:
            requested = auth[offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            if requested:
                try:
                    database.query("USE " + requested)
                except ValueError:
                    await send([self._error("Unknown database")], 2)
                    return sent
        ok = b"\x00\x00\x00\x02\x00\x00\x00"
        await send([ok], 2)
        for _ in range(100):
            packet = await self._read_packet(reader, 0)
            if not packet or packet[0] == 1:  # COM_QUIT
                break
            if packet[0] == 14:  # COM_PING
                await send([ok])
                continue
            if packet[0] not in (2, 3):  # COM_INIT_DB / COM_QUERY
                await send([self._error("Unsupported command")])
                continue
            query = packet[1:].decode("utf-8", errors="replace")
            if packet[0] == 2:
                query = "USE " + query
            succeeded = True
            try:
                columns, rows = database.query(query)
                if not columns:
                    packets = [ok]
                else:
                    eof = b"\xfe\x00\x00\x02\x00"
                    packets = [bytes([len(columns)])]
                    for column in columns:
                        packets.append(b"".join(length_encoded(v) for v in ("def", database.database, "", "", column, column))
                                       + b"\x0c\x21\x00\x00\x04\x00\x00\xfd\x00\x00\x00\x00\x00")
                    packets += [eof] + [b"".join(length_encoded(v) for v in row) for row in rows] + [eof]
            except ValueError as exc:
                succeeded = False
                packets = [self._error(str(exc))]
            emit("database_query", {
                "query": captured_text(query, enabled=self.capture_commands, max_bytes=self.max_payload_bytes, max_chars=4096),
                "database": captured_text(database.database, enabled=self.capture_commands, max_bytes=self.max_payload_bytes, max_chars=128),
                "succeeded": succeeded,
            })
            await send(packets)
        return sent

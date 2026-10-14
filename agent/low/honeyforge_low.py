import asyncio
import json
import sqlite3
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4
from urllib.request import Request, urlopen


class EventQueue:
    """Durable FIFO for Security Events awaiting acknowledgement."""

    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)
        self.journal_mode = str(
            self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        ).lower()
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                body TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

    def enqueue(self, event: dict[str, Any]) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO pending_events(event_id, body) VALUES (?, ?)",
                (event["id"], json.dumps(event, separators=(",", ":"))),
            )

    def pending(self, *, limit: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT body FROM pending_events ORDER BY sequence LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def pending_count(self) -> int:
        return int(
            self.connection.execute("SELECT count(*) FROM pending_events").fetchone()[0]
        )

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self.connection:
            self.connection.executemany(
                "DELETE FROM pending_events WHERE event_id = ?",
                [(event_id,) for event_id in event_ids],
            )

    def close(self) -> None:
        self.connection.close()


class AgentClient:
    """Verified-TLS adapter for the masked Agent interface."""

    def __init__(
        self, base_url: str, trap_secret: str, *, ca_file: Path | None = None
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Agent API requires HTTPS")
        self.base_url = base_url.rstrip("/")
        self.trap_secret = trap_secret
        self.ssl_context = ssl.create_default_context(cafile=ca_file)

    async def fetch_configuration(self) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}/assets/v2/config",
            headers={"Authorization": f"Bearer {self.trap_secret}"},
        )
        response = await asyncio.to_thread(
            urlopen, request, context=self.ssl_context, timeout=10
        )
        return dict(json.loads(response.read()))

    async def deliver_pending(self, queue: EventQueue, *, limit: int = 500) -> int:
        events = queue.pending(limit=limit)
        if not events:
            return 0
        request = Request(
            f"{self.base_url}/assets/v2/init",
            data=json.dumps({"events": events}, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {self.trap_secret}",
                "Content-Type": "application/javascript",
            },
            method="POST",
        )
        response = await asyncio.to_thread(
            urlopen, request, context=self.ssl_context, timeout=10
        )
        acknowledgement = json.loads(response.read())
        accepted = list(acknowledgement["accepted"])
        queue.acknowledge(accepted)
        return len(accepted)


class LowSshAgent:
    """Expose one static SSH banner and queue normalized connection activity."""

    def __init__(
        self,
        *,
        trap_id: UUID,
        host: str,
        port: int,
        banner: str,
        queue: EventQueue,
        connection_limit: int = 100,
        idle_timeout_seconds: float = 10,
    ) -> None:
        self.trap_id = trap_id
        self.host = host
        self.requested_port = port
        self.banner = banner
        self.queue = queue
        self.connection_limit = connection_limit
        self.idle_timeout_seconds = idle_timeout_seconds
        self._active_connections = 0
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            return self.requested_port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._accept_connection, self.host, self.requested_port
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*tuple(self._handlers), return_exceptions=True)
        await self._server.wait_closed()
        self._server = None

    def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._handlers.add(task)
        task.add_done_callback(self._handlers.discard)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._active_connections >= self.connection_limit:
            writer.close()
            await writer.wait_closed()
            return
        self._active_connections += 1
        self._writers.add(writer)
        attack_session_id: str | None = None
        source_ip = "unknown"
        source_port = 0
        banner_bytes = b""
        try:
            peer = writer.get_extra_info("peername")
            source_ip = str(peer[0])
            source_port = int(peer[1])
            attack_session_id = str(uuid4())
            opened_at = datetime.now(UTC).isoformat()
            banner_bytes = f"{self.banner}\r\n".encode()
            self.queue.enqueue(
                self._event(
                    attack_session_id=attack_session_id,
                    event_type="connection_opened",
                    observed_at=opened_at,
                    source_ip=source_ip,
                    source_port=source_port,
                    payload={"banner": self.banner},
                )
            )
            writer.write(banner_bytes)
            await writer.drain()
            try:
                await asyncio.wait_for(
                    reader.read(), timeout=self.idle_timeout_seconds
                )
            except TimeoutError:
                pass
        finally:
            if attack_session_id is not None:
                self.queue.enqueue(
                    self._event(
                        attack_session_id=attack_session_id,
                        event_type="connection_closed",
                        observed_at=datetime.now(UTC).isoformat(),
                        source_ip=source_ip,
                        source_port=source_port,
                        payload={"bytes_sent": len(banner_bytes)},
                    )
                )
            writer.close()
            self._writers.discard(writer)
            self._active_connections -= 1

    def _event(
        self,
        *,
        attack_session_id: str,
        event_type: str,
        observed_at: str,
        source_ip: str,
        source_port: int,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "schema_version": 1,
            "trap_id": str(self.trap_id),
            "attack_session_id": attack_session_id,
            "event_type": event_type,
            "observed_at": observed_at,
            "source_ip": source_ip,
            "source_port": source_port,
            "target_service": "ssh",
            "target_port": self.port,
            "payload": payload,
        }

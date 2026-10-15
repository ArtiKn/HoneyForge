import asyncio
import json
import logging
import sqlite3
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from honeyforge_common.logging import redact_credentials

log = logging.getLogger(__name__)

class JsonLogFormatter(logging.Formatter):
    """Render Agent operational logs without serializing arbitrary input fields."""

    _safe_fields = ("event_id", "event_bytes")

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": redact_credentials(record.getMessage()),
        }
        for field in self._safe_fields:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        return json.dumps(payload, separators=(",", ":"))


class EventQueue:
    """Durable FIFO for Security Events awaiting acknowledgement."""

    def __init__(
        self,
        path: Path,
        *,
        max_events: int = 100_000,
        max_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        if max_events < 1 or max_bytes < 1:
            raise ValueError("EventQueue limits must be positive")
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.connection = sqlite3.connect(path)
        self.journal_mode = str(
            self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        ).lower()
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                body TEXT NOT NULL,
                size_bytes INTEGER NOT NULL
            )
            """
        )
        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(pending_events)")
        }
        if "size_bytes" not in columns:
            self.connection.execute(
                "ALTER TABLE pending_events ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0"
            )
            for sequence, body in self.connection.execute(
                "SELECT sequence, body FROM pending_events"
            ):
                self.connection.execute(
                    "UPDATE pending_events SET size_bytes = ? WHERE sequence = ?",
                    (len(body.encode()), sequence),
                )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantined_event_records (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                body TEXT NOT NULL,
                reason TEXT NOT NULL,
                quarantined_at TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS buffer_loss_reports (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                dropped_events INTEGER NOT NULL,
                dropped_bytes INTEGER NOT NULL,
                first_dropped_at TEXT NOT NULL,
                last_dropped_at TEXT NOT NULL
            )
            """
        )
        self._pending_count, self._pending_bytes = self.connection.execute(
            "SELECT count(*), coalesce(sum(size_bytes), 0) FROM pending_events"
        ).fetchone()
        with self.connection:
            self._enforce_limits()

    def enqueue(self, event: dict[str, Any]) -> None:
        body = json.dumps(event, separators=(",", ":"))
        with self.connection:
            inserted = self.connection.execute(
                """
                INSERT OR IGNORE INTO pending_events(event_id, body, size_bytes)
                VALUES (?, ?, ?)
                """,
                (event["id"], body, len(body.encode())),
            )
            if inserted.rowcount:
                self._pending_count += 1
                self._pending_bytes += len(body.encode())
            self._enforce_limits()

    def pending(self, *, limit: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT body FROM pending_events ORDER BY sequence LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def pending_batch(
        self, *, max_events: int = 500, max_bytes: int = 1024 * 1024
    ) -> list[dict[str, Any]]:
        """Return the oldest request-sized batch, quarantining unsendable records."""

        events: list[dict[str, Any]] = []
        request_bytes = len(b'{"events":[]}')
        after_sequence = 0
        while len(events) < max_events:
            row = self.connection.execute(
                """
                SELECT sequence, event_id, body, size_bytes
                FROM pending_events
                WHERE sequence > ?
                ORDER BY sequence LIMIT 1
                """,
                (after_sequence,),
            ).fetchone()
            if row is None:
                break
            sequence, event_id, body, event_bytes = row
            after_sequence = sequence
            separator_bytes = 1 if events else 0
            candidate_bytes = request_bytes + event_bytes + separator_bytes
            if candidate_bytes > max_bytes:
                if not events:
                    self.quarantine(
                        event_id,
                        f"record exceeds {max_bytes}-byte delivery request limit",
                    )
                    continue
                break
            events.append(json.loads(body))
            request_bytes = candidate_bytes
        return events

    def pending_count(self) -> int:
        return self._pending_count

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self.connection:
            for event_id in event_ids:
                row = self.connection.execute(
                    "SELECT size_bytes FROM pending_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    continue
                self.connection.execute(
                    "DELETE FROM pending_events WHERE event_id = ?", (event_id,)
                )
                self._pending_count -= 1
                self._pending_bytes -= row[0]

    def quarantine(self, event_id: str, reason: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection:
            pending = self.connection.execute(
                "SELECT size_bytes FROM pending_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if pending is None:
                return
            self.connection.execute(
                """
                INSERT OR IGNORE INTO quarantined_event_records(
                    event_id, body, reason, quarantined_at
                )
                SELECT event_id, body, ?, ? FROM pending_events WHERE event_id = ?
                """,
                (reason, now, event_id),
            )
            self.connection.execute(
                "DELETE FROM pending_events WHERE event_id = ?", (event_id,)
            )
            self._pending_count -= 1
            self._pending_bytes -= pending[0]

    def quarantined(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT body, reason FROM quarantined_event_records ORDER BY sequence
            """
        ).fetchall()
        return [
            {"event": json.loads(body), "reason": reason} for body, reason in rows
        ]

    def buffer_loss_report(self) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT dropped_events, dropped_bytes, first_dropped_at, last_dropped_at
            FROM buffer_loss_reports WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            return None
        return {
            "dropped_events": row[0],
            "dropped_bytes": row[1],
            "first_dropped_at": row[2],
            "last_dropped_at": row[3],
        }

    def acknowledge_buffer_loss(self, report: dict[str, Any] | None = None) -> None:
        with self.connection:
            if report is None:
                self.connection.execute(
                    "DELETE FROM buffer_loss_reports WHERE singleton = 1"
                )
                return
            self.connection.execute(
                """
                DELETE FROM buffer_loss_reports
                WHERE singleton = 1
                  AND dropped_events = ?
                  AND dropped_bytes = ?
                  AND last_dropped_at = ?
                """,
                (
                    report["dropped_events"],
                    report["dropped_bytes"],
                    report["last_dropped_at"],
                ),
            )

    def _enforce_limits(self) -> None:
        while (
            self._pending_count > self.max_events
            or self._pending_bytes > self.max_bytes
        ):
            dropped = self.connection.execute(
                """
                SELECT sequence, event_id, size_bytes
                FROM pending_events ORDER BY sequence LIMIT 1
                """
            ).fetchone()
            if dropped is None:
                return
            sequence, event_id, event_bytes = dropped
            self.connection.execute(
                "DELETE FROM pending_events WHERE sequence = ?", (sequence,)
            )
            self._pending_count -= 1
            self._pending_bytes -= event_bytes
            now = datetime.now(UTC).isoformat()
            self.connection.execute(
                """
                INSERT INTO buffer_loss_reports(
                    singleton, dropped_events, dropped_bytes,
                    first_dropped_at, last_dropped_at
                ) VALUES (1, 1, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    dropped_events = dropped_events + 1,
                    dropped_bytes = dropped_bytes + excluded.dropped_bytes,
                    last_dropped_at = excluded.last_dropped_at
                """,
                (event_bytes, now, now),
            )
            log.warning(
                "Security Event buffer overflow; oldest record removed",
                extra={"event_id": event_id, "event_bytes": event_bytes},
            )

    def close(self) -> None:
        self.connection.close()


class AgentClient:
    """Verified-TLS adapter for the masked Agent interface."""

    def __init__(
        self, base_url: str, trap_secret: str, *, ca_file: Path | None = None,
        secret_file: Path | None = None,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Agent API requires HTTPS")
        self.base_url = base_url.rstrip("/")
        self.trap_secret = trap_secret
        self._secret_file = secret_file
        self.ssl_context = ssl.create_default_context(cafile=ca_file)

    def reload_secret(self) -> bool:
        """Re-read the Trap secret from disk after an operator re-enrollment.

        Returns whether a different secret was loaded; the next request then
        authenticates with it, so a restored Trap recovers without a restart.
        """

        if self._secret_file is None:
            return False
        try:
            secret = self._secret_file.read_text(encoding="utf-8").strip()
        except OSError:
            return False
        if secret and secret != self.trap_secret:
            self.trap_secret = secret
            return True
        return False

    async def fetch_configuration(self) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}/assets/v2/config",
            headers={"Authorization": f"Bearer {self.trap_secret}"},
        )
        response = await asyncio.to_thread(
            urlopen, request, context=self.ssl_context, timeout=10
        )
        return dict(json.loads(response.read()))

    async def report_health(
        self,
        queue: EventQueue,
        *,
        agent_version: str,
        active_profile_version: int,
        enabled: bool,
        configuration_errors: list[str],
    ) -> None:
        loss_report = queue.buffer_loss_report()
        payload: dict[str, Any] = {
            "agent_version": agent_version,
            "active_profile_version": active_profile_version,
            "enabled": enabled,
            "buffer_depth": queue.pending_count(),
            "configuration_errors": configuration_errors,
        }
        if loss_report is not None:
            payload["buffer_loss"] = loss_report
        request = Request(
            f"{self.base_url}/assets/v2/health",
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {self.trap_secret}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        await asyncio.to_thread(
            urlopen, request, context=self.ssl_context, timeout=10
        )
        if loss_report is not None:
            queue.acknowledge_buffer_loss(loss_report)

    async def deliver_pending(self, queue: EventQueue, *, limit: int = 500) -> int:
        events = queue.pending_batch(max_events=min(limit, 500))
        if not events:
            return 0
        return await self._deliver_events(queue, events)

    async def _deliver_events(
        self, queue: EventQueue, events: list[dict[str, Any]]
    ) -> int:
        request_body = json.dumps(
            {"events": events}, separators=(",", ":")
        ).encode()
        request = Request(
            f"{self.base_url}/assets/v2/init",
            data=request_body,
            headers={
                "Authorization": f"Bearer {self.trap_secret}",
                "Content-Type": "application/javascript",
            },
            method="POST",
        )
        try:
            response = await asyncio.to_thread(
                urlopen, request, context=self.ssl_context, timeout=10
            )
        except HTTPError as exc:
            if exc.code != 422:
                raise
            if len(events) > 1:
                midpoint = len(events) // 2
                first = await self._deliver_events(queue, events[:midpoint])
                second = await self._deliver_events(queue, events[midpoint:])
                return first + second
            error_body = exc.read()
            try:
                detail = json.loads(error_body).get("detail", "invalid event")
            except (json.JSONDecodeError, UnicodeDecodeError):
                detail = "invalid event"
            reason = (
                detail
                if isinstance(detail, str)
                else json.dumps(detail, separators=(",", ":"))
            )
            queue.quarantine(events[0]["id"], reason)
            log.warning(
                "Security Event record moved to quarantine",
                extra={"event_id": events[0]["id"]},
            )
            return 0
        acknowledgement = json.loads(response.read())
        sent_ids = {event["id"] for event in events}
        accepted = [
            event_id
            for event_id in acknowledgement["accepted"]
            if event_id in sent_ids
        ]
        queue.acknowledge(accepted)
        return len(accepted)


class _LowTcpService:
    """Deep TCP listener seam shared by Low protocol adapters."""

    protocol: str

    def __init__(
        self,
        *,
        trap_id: UUID,
        host: str,
        port: int,
        queue: EventQueue,
        connection_limit: int = 100,
        idle_timeout_seconds: float = 10,
        max_input_bytes: int = 64 * 1024,
        response_delay_ms: int = 0,
    ) -> None:
        self.trap_id = trap_id
        self.host = host
        self.requested_port = port
        self.queue = queue
        self.connection_limit = connection_limit
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_input_bytes = max_input_bytes
        self.response_delay_seconds = max(response_delay_ms, 0) / 1000.0
        self._active_connections = 0
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._committed = asyncio.Event()

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            return self.requested_port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        await self.prepare()
        await self.start_accepting()
        self.commit()

    async def prepare(self) -> None:
        self._server = await asyncio.start_server(
            self._accept_connection, self.host, self.requested_port,
            start_serving=False,
        )

    async def start_accepting(self) -> None:
        if self._server is None:
            raise RuntimeError("Low Trap service is not prepared")
        await self._server.start_serving()

    def commit(self) -> None:
        self._committed.set()

    async def stop(self) -> None:
        await self.stop_accepting()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*tuple(self._handlers), return_exceptions=True)

    async def stop_accepting(self) -> None:
        if self._server is None:
            return
        self._server.close()
        self._server = None

    async def wait_drained(self) -> None:
        if self._handlers:
            await asyncio.gather(*tuple(self._handlers), return_exceptions=True)

    def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._active_connections >= self.connection_limit:
            writer.close()
            return
        self._active_connections += 1
        self._writers.add(writer)
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._handlers.add(task)
        task.add_done_callback(self._handlers.discard)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await self._committed.wait()
        peer = writer.get_extra_info("peername")
        source_ip = str(peer[0]) if peer else "unknown"
        source_port = int(peer[1]) if peer else 0
        attack_session_id = self.session_id_for(source_ip, source_port)
        banner = self.banner()
        self.queue.enqueue(
            self._event(
                attack_session_id=attack_session_id,
                event_type="connection_opened",
                observed_at=datetime.now(UTC).isoformat(),
                source_ip=source_ip,
                source_port=source_port,
                payload={"banner": banner},
            )
        )
        self._writers.add(writer)
        bytes_sent = 0
        try:
            try:
                bytes_sent = await self.serve(
                    reader,
                    writer,
                    attack_session_id=attack_session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                )
            except (ConnectionError, OSError, TimeoutError):
                pass
        finally:
            self.queue.enqueue(
                self._event(
                    attack_session_id=attack_session_id,
                    event_type="connection_closed",
                    observed_at=datetime.now(UTC).isoformat(),
                    source_ip=source_ip,
                    source_port=source_port,
                    payload={"bytes_sent": bytes_sent},
                )
            )
            writer.close()
            await writer.wait_closed()
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
            "target_service": self.protocol,
            "target_port": self.port,
            "payload": payload,
        }

    def banner(self) -> str:
        raise NotImplementedError

    def session_id_for(self, source_ip: str, source_port: int) -> str:
        return str(uuid4())

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, **kwargs: str) -> int:
        raise NotImplementedError


class LowHttpAttackSessionRegistry:
    """Correlate HTTP activity by source within one Trap runtime."""

    def __init__(self, *, timeout: timedelta = timedelta(minutes=15)) -> None:
        if timeout <= timedelta(0):
            raise ValueError("HTTP session timeout must be positive")
        self.timeout = timeout
        self._sessions: dict[tuple[UUID, str], tuple[str, datetime, int, Any]] = {}
        self._timers: dict[tuple[UUID, str], asyncio.TimerHandle] = {}

    def get(
        self,
        trap_id: UUID,
        source_ip: str,
        source_port: int,
        on_expire: Any,
    ) -> str:
        now = datetime.now(UTC)
        key = (trap_id, source_ip)
        existing = self._sessions.get(key)
        if existing is not None and now - existing[1] <= self.timeout:
            session_id = existing[0]
        else:
            if existing is not None:
                self._expire(key, existing[0])
            session_id = str(uuid4())
        self._sessions[key] = (session_id, now, source_port, on_expire)
        timer = self._timers.pop(key, None)
        if timer is not None:
            timer.cancel()
        self._timers[key] = asyncio.get_running_loop().call_later(
            self.timeout.total_seconds(), self._expire, key, session_id
        )
        return session_id

    def _expire(self, key: tuple[UUID, str], session_id: str) -> None:
        current = self._sessions.get(key)
        if current is None or current[0] != session_id:
            return
        self._sessions.pop(key, None)
        self._timers.pop(key, None)
        current[3](session_id, key[1], current[2], datetime.now(UTC))


class LowHttpAgent(_LowTcpService):
    protocol = "http"

    def __init__(
        self,
        *,
        banner: str | None = None,
        session_registry: LowHttpAttackSessionRegistry | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.http_banner = banner or "nginx/1.24.0"
        self._session_registry = session_registry or LowHttpAttackSessionRegistry()

    def banner(self) -> str:
        return self.http_banner

    def session_id_for(self, source_ip: str, source_port: int) -> str:
        return self._session_registry.get(
            self.trap_id,
            source_ip,
            source_port,
            self._enqueue_expired_session,
        )

    def _enqueue_expired_session(
        self,
        session_id: str,
        source_ip: str,
        source_port: int,
        observed_at: datetime,
    ) -> None:
        self.queue.enqueue(
            self._event(
                attack_session_id=session_id,
                event_type="connection_closed",
                observed_at=observed_at.isoformat(),
                source_ip=source_ip,
                source_port=source_port,
                payload={"bytes_sent": 0, "session_expired": True},
            )
        )

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, **kwargs: str) -> int:
        chunks: list[bytes] = []
        total = 0
        while b"\r\n\r\n" not in b"".join(chunks):
            chunk = await asyncio.wait_for(reader.read(1024), timeout=self.idle_timeout_seconds)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > self.max_input_bytes:
                return 0
        raw = b"".join(chunks)
        if len(raw) > self.max_input_bytes:
            return 0
        line = raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = line.split(" ", 2)
        if len(parts) == 3:
            method, path, http_version = parts
            self.queue.enqueue(
                self._event(
                    attack_session_id=kwargs["attack_session_id"],
                    event_type="http_request",
                    observed_at=datetime.now(UTC).isoformat(),
                    source_ip=kwargs["source_ip"],
                    source_port=int(kwargs["source_port"]),
                    payload={
                        "method": method,
                        "path": path,
                        "http_version": http_version,
                        "bytes_received": len(raw),
                    },
                )
            )
        body = b"<html><title>HoneyForge</title><body>HoneyForge</body></html>"
        response = (
            b"HTTP/1.1 200 OK\r\nServer: "
            + self.http_banner.encode()
            + b"\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        if self.response_delay_seconds:
            await asyncio.sleep(self.response_delay_seconds)
        writer.write(response)
        await writer.drain()
        return len(response)


class LowMySqlAgent(_LowTcpService):
    protocol = "mysql"

    def __init__(self, *, banner: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.mysql_banner = banner or "8.0.36-HoneyForge"

    def banner(self) -> str:
        return self.mysql_banner

    def _handshake(self) -> bytes:
        payload = (
            b"\x0a"
            + self.mysql_banner.encode()
            + b"\x00"
            + (1).to_bytes(4, "little")
            + b"abcdefgh\x00"
            + (0xFFFF).to_bytes(2, "little")
            + b"\x21"
            + (2).to_bytes(2, "little")
            + (0xFFFF).to_bytes(2, "little")
            + b"\x15"
            + b"\x00" * 10
            + b"ijklmnopqrst\x00"
            + b"mysql_native_password\x00"
        )
        return len(payload).to_bytes(3, "little") + b"\x00" + payload

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, **kwargs: str) -> int:
        handshake = self._handshake()
        if self.response_delay_seconds:
            await asyncio.sleep(self.response_delay_seconds)
        writer.write(handshake)
        await writer.drain()
        received = await asyncio.wait_for(
            reader.read(self.max_input_bytes + 1), timeout=self.idle_timeout_seconds
        )
        if len(received) > self.max_input_bytes:
            return len(handshake)
        return len(handshake)


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
        response_delay_ms: int = 0,
    ) -> None:
        self.trap_id = trap_id
        self.host = host
        self.requested_port = port
        self.banner = banner
        self.queue = queue
        self.connection_limit = connection_limit
        self.idle_timeout_seconds = idle_timeout_seconds
        self.response_delay_seconds = max(response_delay_ms, 0) / 1000.0
        self._active_connections = 0
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._committed = asyncio.Event()

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            return self.requested_port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        await self.prepare()
        await self.start_accepting()
        self.commit()

    async def prepare(self) -> None:
        self._server = await asyncio.start_server(
            self._accept_connection, self.host, self.requested_port,
            start_serving=False,
        )

    async def start_accepting(self) -> None:
        if self._server is None:
            raise RuntimeError("Low SSH Service is not prepared")
        await self._server.start_serving()

    def commit(self) -> None:
        self._committed.set()

    async def stop(self) -> None:
        await self.stop_accepting()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*tuple(self._handlers), return_exceptions=True)

    async def stop_accepting(self) -> None:
        if self._server is None:
            return
        self._server.close()
        self._server = None

    async def wait_drained(self) -> None:
        if self._handlers:
            await asyncio.gather(*tuple(self._handlers), return_exceptions=True)

    def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._handlers.add(task)
        task.add_done_callback(self._handlers.discard)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await self._committed.wait()
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
            if self.response_delay_seconds:
                await asyncio.sleep(self.response_delay_seconds)
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

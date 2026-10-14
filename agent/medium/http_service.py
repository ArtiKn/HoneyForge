"""Interactive fake-HTTP module for a Medium Trap."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from html import escape
from http.cookies import SimpleCookie
from secrets import token_urlsafe
from typing import Any
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from agent.low.honeyforge_low import EventQueue


class HttpAttackSessionRegistry:
    """Trap-scoped source correlation shared across HTTP service instances."""

    def __init__(self, timeout_seconds: float = 15 * 60) -> None:
        if timeout_seconds <= 0:
            raise ValueError("HTTP session timeout must be positive")
        self.timeout_seconds = timeout_seconds
        self._sessions: dict[str, tuple[str, datetime, int, Any]] = {}
        self._timers: dict[str, asyncio.TimerHandle] = {}

    def get(self, source_ip: str, source_port: int, on_expire: Any) -> str:
        now = datetime.now(UTC)
        existing = self._sessions.get(source_ip)
        if existing is not None and now - existing[1] < timedelta(seconds=self.timeout_seconds):
            session_id = existing[0]
        else:
            if existing is not None:
                self._expire(source_ip, existing[0])
            session_id = str(uuid4())
        self._sessions[source_ip] = (session_id, now, source_port, on_expire)
        timer = self._timers.pop(source_ip, None)
        if timer is not None:
            timer.cancel()
        self._timers[source_ip] = asyncio.get_running_loop().call_later(
            self.timeout_seconds, self._expire, source_ip, session_id
        )
        return session_id

    def _expire(self, source_ip: str, session_id: str) -> None:
        current = self._sessions.get(source_ip)
        if current is None or current[0] != session_id:
            return
        self._sessions.pop(source_ip, None)
        self._timers.pop(source_ip, None)
        current[3](session_id, source_ip, current[2])


class MediumHttpService:
    """Expose a bounded fictitious admin flow behind a small listener interface."""

    def __init__(
        self,
        *,
        trap_id: UUID,
        host: str,
        port: int,
        queue: EventQueue,
        banner: str = "nginx/1.24.0",
        connection_limit: int = 100,
        idle_timeout_seconds: float = 10,
        max_input_bytes: int = 64 * 1024,
        session_timeout_seconds: float = 15 * 60,
        session_registry: HttpAttackSessionRegistry | None = None,
    ) -> None:
        if min(
            connection_limit,
            idle_timeout_seconds,
            max_input_bytes,
            session_timeout_seconds,
        ) <= 0:
            raise ValueError("Medium HTTP limits must be positive")
        self.trap_id = trap_id
        self.host = host
        self.requested_port = port
        self.queue = queue
        self.banner = banner.replace("\r", "").replace("\n", "")
        self.connection_limit = connection_limit
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_input_bytes = max_input_bytes
        self.session_timeout_seconds = session_timeout_seconds
        self._server: asyncio.Server | None = None
        self._active_connections = 0
        self._handlers: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._committed = asyncio.Event()
        self._session_registry = session_registry or HttpAttackSessionRegistry(
            session_timeout_seconds
        )
        self._authenticated_sessions: dict[str, str] = {}

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
            raise RuntimeError("Medium HTTP Service is not prepared")
        await self._server.start_serving()

    def commit(self) -> None:
        self._committed.set()

    async def stop_accepting(self) -> None:
        if self._server is None:
            return
        self._server.close()
        self._server = None

    async def wait_drained(self) -> None:
        if self._handlers:
            await asyncio.gather(*tuple(self._handlers), return_exceptions=True)

    async def stop(self) -> None:
        await self.stop_accepting()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._handlers):
            task.cancel()
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
        source_ip, source_port = (str(peer[0]), int(peer[1])) if peer else ("unknown", 0)
        attack_session_id = self._attack_session(source_ip, source_port)
        bytes_sent = 0
        try:
            self._enqueue(
                attack_session_id,
                "connection_opened",
                source_ip,
                source_port,
                {"banner": self.banner},
            )
            request = await self._read_request(reader)
            if request is None:
                return
            method, target, version, headers, body, bytes_received = request
            self._enqueue(
                attack_session_id,
                "http_request",
                source_ip,
                source_port,
                {
                    "method": method,
                    "path": target,
                    "http_version": version,
                    "bytes_received": bytes_received,
                },
            )
            status, response_headers, content = self._route(
                method, target, headers, body, attack_session_id, source_ip, source_port
            )
            response = self._response(status, response_headers, content)
            writer.write(response)
            await writer.drain()
            bytes_sent = len(response)
        except (ConnectionError, OSError, asyncio.TimeoutError, ValueError):
            pass
        finally:
            self._enqueue(
                attack_session_id,
                "connection_closed",
                source_ip,
                source_port,
                {"bytes_sent": bytes_sent},
            )
            writer.close()
            await writer.wait_closed()
            self._writers.discard(writer)
            self._active_connections -= 1

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> tuple[str, str, str, dict[str, str], bytes, int] | None:
        try:
            header_block = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self.idle_timeout_seconds
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return None
        if len(header_block) > self.max_input_bytes:
            return None
        lines = header_block[:-4].split(b"\r\n")
        request_line = lines[0].decode("latin-1", errors="replace").split(" ", 2)
        if len(request_line) != 3:
            return None
        method, target, version = request_line
        if len(method) > 16 or len(target) > 2048 or version not in ("HTTP/1.0", "HTTP/1.1"):
            return None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                headers[name.decode("latin-1").lower()] = value.decode("latin-1").strip()
        content_length = int(headers.get("content-length", "0"))
        if content_length < 0 or len(header_block) + content_length > self.max_input_bytes:
            return None
        body = await asyncio.wait_for(
            reader.readexactly(content_length), timeout=self.idle_timeout_seconds
        ) if content_length else b""
        return method, target, version, headers, body, len(header_block) + len(body)

    def _route(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
        attack_session_id: str,
        source_ip: str,
        source_port: int,
    ) -> tuple[str, dict[str, str], str]:
        path = target.split("?", 1)[0]
        if method == "GET" and path == "/":
            return "302 Found", {"Location": "/login"}, ""
        if method == "GET" and path == "/login":
            return "200 OK", {}, self._login_page()
        if method == "POST" and path == "/login":
            fields = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            username = fields.get("username", [""])[0][:256]
            password = fields.get("password", [""])[0][:1024]
            accepted = bool(username and password)
            self._enqueue(
                attack_session_id,
                "authentication_attempt",
                source_ip,
                source_port,
                {
                    "username": username or "unknown",
                    "password": password,
                    "accepted": accepted,
                },
            )
            if accepted:
                fake_token = token_urlsafe(24)
                self._authenticated_sessions[attack_session_id] = fake_token
                return (
                    "302 Found",
                    {
                        "Location": "/admin",
                        "Set-Cookie": (
                            f"hf_admin={fake_token}; HttpOnly; SameSite=Strict"
                        ),
                    },
                    "",
                )
            return "401 Unauthorized", {}, self._login_page("Invalid credentials")
        if method == "GET" and path == "/admin":
            cookies = SimpleCookie()
            cookies.load(headers.get("cookie", ""))
            supplied = cookies.get("hf_admin")
            expected = self._authenticated_sessions.get(attack_session_id)
            if supplied is None or supplied.value != expected:
                return "302 Found", {"Location": "/login"}, ""
            return "200 OK", {}, self._admin_page()
        return "404 Not Found", {}, self._page("Not found", "The requested page was not found.")

    def _attack_session(self, source_ip: str, source_port: int) -> str:
        return self._session_registry.get(
            source_ip, source_port, self._enqueue_expired_session
        )

    def _enqueue_expired_session(
        self, attack_session_id: str, source_ip: str, source_port: int
    ) -> None:
        self._authenticated_sessions.pop(attack_session_id, None)
        self._enqueue(
            attack_session_id,
            "connection_closed",
            source_ip,
            source_port,
            {"bytes_sent": 0, "session_expired": True},
        )

    def _response(self, status: str, headers: dict[str, str], content: str) -> bytes:
        body = content.encode()
        response_headers = {
            "Server": self.banner,
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
            **headers,
        }
        serialized = "".join(f"{name}: {value}\r\n" for name, value in response_headers.items())
        return f"HTTP/1.1 {status}\r\n{serialized}\r\n".encode() + body

    @classmethod
    def _login_page(cls, message: str = "") -> str:
        detail = f"<p>{escape(message)}</p>" if message else ""
        return cls._page(
            "Operations Console",
            f"{detail}<form method='post' action='/login'>"
            "<label>Username <input name='username' autocomplete='username'></label>"
            "<label>Password <input name='password' type='password'></label>"
            "<button type='submit'>Sign in</button></form>",
        )

    @classmethod
    def _admin_page(cls) -> str:
        return cls._page(
            "System Overview",
            "<nav>Overview · Users · Audit Log</nav>"
            "<h2>Infrastructure</h2><p>3 nodes online</p>"
            "<h2>Recent activity</h2><p>Backup completed successfully</p>",
        )

    @staticmethod
    def _page(title: str, content: str) -> str:
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{escape(title)}</title></head><body><main><h1>{escape(title)}</h1>"
            f"{content}</main></body></html>"
        )

    def _enqueue(
        self,
        attack_session_id: str,
        event_type: str,
        source_ip: str,
        source_port: int,
        payload: dict[str, Any],
    ) -> None:
        self.queue.enqueue(
            {
                "id": str(uuid4()),
                "schema_version": 1,
                "trap_id": str(self.trap_id),
                "attack_session_id": attack_session_id,
                "event_type": event_type,
                "observed_at": datetime.now(UTC).isoformat(),
                "source_ip": source_ip,
                "source_port": source_port,
                "target_service": "http",
                "target_port": self.port,
                "payload": payload,
            }
        )

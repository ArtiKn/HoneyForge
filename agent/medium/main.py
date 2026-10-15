"""Run the configured Medium-interaction Trap services."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from uuid import UUID, uuid4

import asyncssh

from agent.low.honeyforge_low import AgentClient, EventQueue, JsonLogFormatter
from agent.low.profile_runtime import (
    ProfileRuntime,
    TrapService,
    report_runtime_health,
)
from agent.medium.http_service import HttpAttackSessionRegistry, MediumHttpService

log = logging.getLogger("honeyforge-agent")


@dataclass
class _AttackConnection:
    attack_session_id: str
    source_ip: str
    source_port: int
    bytes_sent: int = 0
    username: str = "attacker"
    auth_attempts: int = 0


class _FakeShellSession(asyncssh.SSHServerSession[str]):
    def __init__(self, service: "MediumSshService", attack: _AttackConnection) -> None:
        self.service = service
        self.attack = attack
        self.channel: asyncssh.SSHServerChannel[str] | None = None
        self.input_buffer = ""
        self.idle_timer: asyncio.TimerHandle | None = None

    def connection_made(self, channel: asyncssh.SSHServerChannel[str]) -> None:
        self.channel = channel

    def shell_requested(self) -> bool:
        return True

    def session_started(self) -> None:
        self._reset_idle_timer()
        self._write("Welcome to Ubuntu 22.04 LTS (HoneyForge)\r\n$ ")

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:
        self._reset_idle_timer()
        self.input_buffer += data
        if len(self.input_buffer.encode()) > self.service.max_input_bytes:
            self.service.close_connection(self.attack)
            return
        while "\n" in self.input_buffer:
            raw_command, self.input_buffer = self.input_buffer.split("\n", 1)
            command = raw_command.rstrip("\r")
            self.service.enqueue(
                self.attack,
                "command_entered",
                {"command": command},
            )
            response, should_close = self.service.command_response(
                command, self.attack.username
            )
            self._write(response)
            if should_close and self.channel is not None:
                self.channel.exit(0)
                self.channel.close()
                return

    def connection_lost(self, exc: Exception | None) -> None:
        if self.idle_timer is not None:
            self.idle_timer.cancel()

    def _reset_idle_timer(self) -> None:
        if self.idle_timer is not None:
            self.idle_timer.cancel()
        self.idle_timer = asyncio.get_running_loop().call_later(
            self.service.idle_timeout_seconds, self._close_idle_session
        )

    def _close_idle_session(self) -> None:
        self.service.close_connection(self.attack)

    def _write(self, response: str) -> None:
        if self.channel is not None:
            self.channel.write(response)
            self.attack.bytes_sent += len(response.encode())


class _FakeSshServer(asyncssh.SSHServer):
    def __init__(self, service: "MediumSshService") -> None:
        self.service = service
        self.connection: asyncssh.SSHServerConnection | None = None
        self.attack: _AttackConnection | None = None

    def connection_made(self, connection: asyncssh.SSHServerConnection) -> None:
        peer = connection.get_extra_info("peername")
        source_ip, source_port = (str(peer[0]), int(peer[1])) if peer else ("unknown", 0)
        if not self.service.accept_connection(connection):
            connection.abort()
            return
        self.connection = connection
        self.attack = _AttackConnection(str(uuid4()), source_ip, source_port)
        self.service.register_session(self.attack, connection)
        self.service.enqueue(
            self.attack, "connection_opened", {"banner": self.service.banner}
        )

    def connection_lost(self, exc: Exception | None) -> None:
        if self.attack is not None:
            self.service.enqueue(
                self.attack,
                "connection_closed",
                {"bytes_sent": self.attack.bytes_sent},
            )
        if self.connection is not None:
            self.service.release_connection(self.connection)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if self.attack is None:
            return False
        self.attack.auth_attempts += 1
        accepted = self.attack.auth_attempts <= self.service.max_attempts
        self.attack.username = username[:256] or "attacker"
        self.service.enqueue(
            self.attack,
            "authentication_attempt",
            {
                "username": username[:256] or "unknown",
                "password": password[:1024],
                "accepted": accepted,
            },
        )
        return accepted

    def session_requested(self) -> _FakeShellSession | bool:
        if self.attack is None:
            return False
        return _FakeShellSession(self.service, self.attack)


class MediumSshService:
    """Real SSH transport backed only by a bounded, literal fake shell."""

    def __init__(
        self,
        *,
        trap_id: UUID,
        host: str,
        port: int,
        queue: EventQueue,
        banner: str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        connection_limit: int = 100,
        idle_timeout_seconds: float = 30,
        max_input_bytes: int = 4096,
        max_attempts: int = 3,
    ) -> None:
        if min(connection_limit, max_input_bytes, max_attempts) < 1:
            raise ValueError("Medium SSH limits must be positive")
        self.trap_id = trap_id
        self.host = host
        self.requested_port = port
        self.queue = queue
        self.banner = banner.removeprefix("SSH-2.0-")
        self.connection_limit = connection_limit
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_input_bytes = max_input_bytes
        self.max_attempts = max_attempts
        self._server: asyncssh.SSHAcceptor | None = None
        self._prepared_socket: socket.socket | None = None
        self._connections: set[asyncssh.SSHServerConnection] = set()
        self._connection_by_session: dict[str, asyncssh.SSHServerConnection] = {}
        self._committed = False

    @property
    def port(self) -> int:
        if self._server is None:
            return self.requested_port
        return int(self._server.get_port())

    async def start(self) -> None:
        await self.prepare()
        await self.start_accepting()
        self.commit()

    async def prepare(self) -> None:
        address = socket.getaddrinfo(
            self.host, self.requested_port, type=socket.SOCK_STREAM,
            flags=socket.AI_PASSIVE,
        )[0]
        prepared_socket = socket.socket(address[0], address[1], address[2])
        prepared_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        prepared_socket.bind(address[4])
        prepared_socket.listen(100)
        prepared_socket.setblocking(False)
        self._prepared_socket = prepared_socket

    async def start_accepting(self) -> None:
        if self._prepared_socket is None:
            raise RuntimeError("Medium SSH Service is not prepared")
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        self._server = await asyncssh.create_server(
            lambda: _FakeSshServer(self),
            sock=self._prepared_socket,
            server_host_keys=[host_key],
            server_version=self.banner,
            login_timeout=self.idle_timeout_seconds,
        )
        self._prepared_socket = None

    def commit(self) -> None:
        self._committed = True

    async def stop(self) -> None:
        await self.stop_accepting()
        if self._prepared_socket is not None:
            self._prepared_socket.close()
            self._prepared_socket = None
        for connection in tuple(self._connections):
            connection.close()

    async def stop_accepting(self) -> None:
        if self._server is None:
            return
        self._server.close()
        self._server = None

    async def wait_drained(self) -> None:
        while self._connections:
            await asyncio.sleep(0.01)

    def accept_connection(self, connection: asyncssh.SSHServerConnection) -> bool:
        if not self._committed or len(self._connections) >= self.connection_limit:
            return False
        self._connections.add(connection)
        return True

    def register_session(
        self, attack: _AttackConnection, connection: asyncssh.SSHServerConnection
    ) -> None:
        self._connection_by_session[attack.attack_session_id] = connection

    def close_connection(self, attack: _AttackConnection) -> None:
        connection = self._connection_by_session.get(attack.attack_session_id)
        if connection is not None:
            connection.abort()

    def release_connection(self, connection: asyncssh.SSHServerConnection) -> None:
        self._connections.discard(connection)
        self._connection_by_session = {
            session_id: item
            for session_id, item in self._connection_by_session.items()
            if item is not connection
        }

    @staticmethod
    def command_response(command: str, username: str) -> tuple[str, bool]:
        responses = {
            "pwd": f"/home/{username}\r\n$ ",
            "whoami": f"{username}\r\n$ ",
            "ls": "README.txt\r\n$ ",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\r\n$ ",
            "uname -a": "Linux honeyforge 5.15.0-generic x86_64 GNU/Linux\r\n$ ",
            "exit": "logout\r\n",
            "logout": "logout\r\n",
        }
        if command in ("exit", "logout"):
            return responses[command], True
        return responses.get(command, "command not found\r\n$ "), False

    def enqueue(
        self,
        attack: _AttackConnection,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        self.queue.enqueue(
            {
                "id": str(uuid4()),
                "schema_version": 1,
                "trap_id": str(self.trap_id),
                "attack_session_id": attack.attack_session_id,
                "event_type": event_type,
                "observed_at": datetime.now(UTC).isoformat(),
                "source_ip": attack.source_ip,
                "source_port": attack.source_port,
                "target_service": "ssh",
                "target_port": self.port,
                "payload": payload,
            }
        )


async def run() -> None:
    secret_file = Path(os.environ["TRAP_SECRET_FILE"])
    ca_file = os.getenv("CENTER_CA_FILE")
    client = AgentClient(
        os.environ["CENTER_URL"],
        secret_file.read_text(encoding="utf-8").strip(),
        ca_file=Path(ca_file) if ca_file else None,
    )
    configuration = await client.fetch_configuration()
    if configuration["interaction_level"] != "medium":
        raise RuntimeError("Medium Trap Agent requires a medium-interaction Trap Profile")
    queue = EventQueue(
        Path(os.environ["EVENT_QUEUE_PATH"]),
        max_events=int(os.getenv("EVENT_QUEUE_MAX_EVENTS", "100000")),
        max_bytes=int(os.getenv("EVENT_QUEUE_MAX_BYTES", str(256 * 1024 * 1024))),
    )
    http_sessions = HttpAttackSessionRegistry()

    def configured_services(
        config: dict[str, Any]
    ) -> list[TrapService]:
        if config["interaction_level"] != "medium":
            raise RuntimeError(
                "Medium Trap Agent requires a medium-interaction Trap Profile"
            )
        result: list[TrapService] = []
        for definition in config["services"]:
            if definition["protocol"] not in ("ssh", "http"):
                raise RuntimeError(
                    f"Unsupported Medium service protocol: {definition['protocol']}"
                )
            settings = definition.get("emulator_settings", {})
            common = {
                "trap_id": UUID(config["trap_id"]),
                "host": os.getenv("LISTEN_HOST", "0.0.0.0"),
                "port": int(definition["internal_port"]),
                "queue": queue,
            }
            if definition["protocol"] == "ssh":
                service: TrapService = MediumSshService(
                    **common,
                    banner=definition.get("banner")
                    or "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                    max_attempts=int(settings.get("max_attempts") or 3),
                )
            else:
                service = MediumHttpService(
                    **common,
                    banner=definition.get("banner") or "nginx/1.24.0",
                    session_registry=http_sessions,
                )
            result.append(service)
        return result

    try:
        runtime = ProfileRuntime(configured_services)
        await runtime.start(configuration)
        health_interval = float(os.getenv("HEALTH_INTERVAL_SECONDS", "30"))
        profile_interval = float(os.getenv("PROFILE_CHECK_INTERVAL_SECONDS", "30"))
        delivery_interval = float(os.getenv("DELIVERY_INTERVAL_SECONDS", "1"))
        next_health_at = 0.0
        next_profile_at = asyncio.get_running_loop().time() + profile_interval
        while True:
            try:
                await client.deliver_pending(queue)
            except (OSError, URLError, ValueError):
                log.exception("Security Event delivery failed; events remain queued")
            now = asyncio.get_running_loop().time()
            if now >= next_profile_at:
                try:
                    if await runtime.refresh(client.fetch_configuration):
                        log.info(
                            "Applied Trap Profile change (enabled=%s, version=%s)",
                            runtime.enabled,
                            runtime.active_profile_version,
                        )
                except (OSError, URLError, RuntimeError, ValueError):
                    log.exception("Trap Profile check or apply failed")
                next_profile_at = now + profile_interval
            if now >= next_health_at:
                try:
                    await report_runtime_health(
                        client,
                        queue,
                        agent_version=os.getenv("AGENT_VERSION", "0.1.0"),
                        runtime=runtime,
                    )
                except (OSError, URLError, ValueError):
                    log.exception("Agent Health Report delivery failed")
                else:
                    next_health_at = now + health_interval
            await asyncio.sleep(delivery_interval)
    finally:
        await runtime.stop()
        queue.close()


if __name__ == "__main__":
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass

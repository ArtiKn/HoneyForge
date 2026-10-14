import asyncio
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from agent.low.honeyforge_low import EventQueue, LowSshAgent
from agent.low.profile_runtime import ProfileApplyError, ProfileRuntime
from agent.medium.http_service import MediumHttpService
from agent.medium.main import MediumSshService


pytestmark = pytest.mark.asyncio


class FakeService:
    def __init__(self, name: str, *, fail_start: bool = False) -> None:
        self.name = name
        self.fail_start = fail_start
        self.accepting = False
        self.prepared = False
        self.stopped = False
        self.fail_stop_accepting = False
        self.fail_stop = False
        self.fail_start_accepting = False
        self.fail_wait_drained = False
        self.committed = False

    async def prepare(self) -> None:
        if self.fail_start:
            raise OSError(f"{self.name} port is occupied")
        self.prepared = True

    async def start_accepting(self) -> None:
        assert self.prepared
        if self.fail_start_accepting:
            raise OSError(f"{self.name} could not start accepting")
        self.accepting = True

    def commit(self) -> None:
        self.committed = True

    async def start(self) -> None:
        await self.prepare()
        await self.start_accepting()
        self.commit()

    async def stop_accepting(self) -> None:
        if self.fail_stop_accepting:
            raise OSError(f"{self.name} could not stop accepting")
        self.accepting = False

    async def wait_drained(self) -> None:
        if self.fail_wait_drained:
            raise OSError(f"{self.name} could not drain")

    async def stop(self) -> None:
        if self.fail_stop:
            raise OSError(f"{self.name} could not stop")
        self.accepting = False
        self.stopped = True


async def test_profile_runtime_rolls_back_all_listeners_after_partial_apply() -> None:
    created: dict[int, list[FakeService]] = {}

    def build(configuration: dict[str, Any]) -> list[FakeService]:
        services = [
            FakeService(name, fail_start=name == "occupied")
            for name in configuration["services"]
        ]
        created[configuration["profile_version"]] = services
        return services

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1, "services": ["ssh", "http"]})

    async def occupied_configuration() -> dict[str, Any]:
        return {"profile_version": 2, "services": ["mysql", "occupied"]}

    with pytest.raises(ProfileApplyError, match="occupied"):
        await runtime.refresh(occupied_configuration)

    assert runtime.active_profile_version == 1
    assert runtime.configuration_errors == ["occupied port is occupied"]
    assert all(service.accepting for service in created[1])
    assert all(service.stopped for service in created[2])
    await asyncio.sleep(0)

    async def recovered_configuration() -> dict[str, Any]:
        return {"profile_version": 3, "services": ["ssh", "http"]}

    assert await runtime.refresh(recovered_configuration) is True
    assert runtime.active_profile_version == 3
    assert runtime.configuration_errors == []
    await runtime.stop()


async def test_profile_runtime_attempts_full_rollback_when_old_stop_fails() -> None:
    services: list[FakeService] = []

    def build(_configuration: dict[str, Any]) -> list[FakeService]:
        service = FakeService(f"service-{len(services)}")
        services.append(service)
        return [service]

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1})
    services[0].fail_stop_accepting = True

    with pytest.raises(ProfileApplyError, match="could not stop accepting"):
        await runtime.apply({"profile_version": 2})

    assert runtime.active_profile_version == 1
    assert services[0].accepting is True
    await runtime.stop()


async def test_profile_runtime_never_commits_partial_candidate_activation() -> None:
    versions: dict[int, list[FakeService]] = {}

    def build(configuration: dict[str, Any]) -> list[FakeService]:
        services = [FakeService(name) for name in configuration["services"]]
        if configuration.get("fail_activation"):
            services[-1].fail_start_accepting = True
        versions[configuration["profile_version"]] = services
        return services

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1, "services": ["ssh"]})
    candidate = {
        "profile_version": 2,
        "services": ["http", "mysql"],
        "fail_activation": True,
    }
    with pytest.raises(ProfileApplyError, match="could not start accepting"):
        await runtime.apply(candidate)

    assert not any(service.committed for service in versions[2])
    assert runtime.active_profile_version == 1
    await runtime.stop()


async def test_profile_runtime_cleans_partial_rollback_activation() -> None:
    versions: dict[int, list[FakeService]] = {}

    def build(configuration: dict[str, Any]) -> list[FakeService]:
        services = [FakeService(name) for name in configuration["services"]]
        if configuration.get("fail_activation"):
            services[-1].fail_start_accepting = True
        versions[configuration["profile_version"]] = services
        return services

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1, "services": ["ssh", "http"]})
    versions[1][1].fail_start_accepting = True

    with pytest.raises(ProfileApplyError, match="last-known-good restart failed"):
        await runtime.apply({
            "profile_version": 2,
            "services": ["candidate", "occupied"],
            "fail_activation": True,
        })

    assert not any(service.accepting for service in versions[1])
    assert all(service.stopped for service in versions[1])
    await runtime.stop()


async def test_profile_runtime_reports_retirement_failure() -> None:
    created: list[FakeService] = []

    def build(_configuration: dict[str, Any]) -> list[FakeService]:
        service = FakeService(f"service-{len(created)}")
        created.append(service)
        return [service]

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1})
    created[0].fail_wait_drained = True
    await runtime.apply({"profile_version": 2})
    for _ in range(10):
        if runtime.configuration_errors:
            break
        await asyncio.sleep(0)

    assert runtime.configuration_errors == [
        "Trap service retirement failed: service-0 could not drain"
    ]
    await runtime.stop()


async def test_profile_runtime_rejects_invalid_candidate_before_handoff() -> None:
    active = FakeService("ssh")

    def build(configuration: dict[str, Any]) -> list[FakeService]:
        if "services" not in configuration:
            raise ValueError("services are required")
        return [active]

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1, "services": ["ssh"]})

    async def invalid_configuration() -> dict[str, Any]:
        return {"profile_version": 2}

    with pytest.raises(ProfileApplyError, match="services are required"):
        await runtime.refresh(invalid_configuration)

    assert runtime.active_profile_version == 1
    assert active.accepting is True
    await runtime.stop()


async def test_profile_runtime_switches_new_connections_without_closing_old_ones(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "profile-runtime.sqlite3")
    requested_port = _free_port()

    def build(configuration: dict[str, Any]) -> list[LowSshAgent]:
        return [
            LowSshAgent(
                trap_id=uuid4(), host="127.0.0.1", port=requested_port,
                banner=configuration["banner"], queue=queue,
            )
        ]

    runtime = ProfileRuntime(build)
    await runtime.start({"profile_version": 1, "banner": "SSH-2.0-old"})
    old_reader, old_writer = await asyncio.open_connection("127.0.0.1", requested_port)
    assert await old_reader.readline() == b"SSH-2.0-old\r\n"

    await runtime.apply({"profile_version": 2, "banner": "SSH-2.0-new"})
    assert not old_reader.at_eof()
    old_writer.write(b"interaction under old version")
    await old_writer.drain()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(old_reader.read(), timeout=0.05)
    new_reader, new_writer = await asyncio.open_connection("127.0.0.1", requested_port)
    assert await new_reader.readline() == b"SSH-2.0-new\r\n"
    assert runtime.active_profile_version == 2

    old_writer.close()
    new_writer.close()
    await old_writer.wait_closed()
    await new_writer.wait_closed()
    await runtime.stop()
    queue.close()


async def test_profile_runtime_switches_complete_medium_service_set(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "profile-runtime-medium.sqlite3")
    ssh_port, http_port = _free_port(), _free_port()

    def build(configuration: dict[str, Any]) -> list[Any]:
        return [
            MediumSshService(
                trap_id=uuid4(), host="127.0.0.1", port=ssh_port, queue=queue,
                banner=configuration["ssh_banner"],
            ),
            MediumHttpService(
                trap_id=uuid4(), host="127.0.0.1", port=http_port, queue=queue,
                banner=configuration["http_banner"],
            ),
        ]

    runtime = ProfileRuntime(build)
    await runtime.start({
        "profile_version": 1,
        "ssh_banner": "OpenSSH_8.9-old",
        "http_banner": "nginx-old",
    })
    await runtime.apply({
        "profile_version": 2,
        "ssh_banner": "OpenSSH_9.9-new",
        "http_banner": "nginx-new",
    })
    try:
        http_reader, http_writer = await asyncio.open_connection(
            "127.0.0.1", http_port
        )
        http_writer.write(b"GET /login HTTP/1.1\r\nHost: trap\r\n\r\n")
        await http_writer.drain()
        response = await http_reader.read()
        assert b"Server: nginx-new" in response
        http_writer.close()
        await http_writer.wait_closed()

        import asyncssh

        async with asyncssh.connect(
            "127.0.0.1", port=ssh_port, username="probe", password="secret",
            known_hosts=None,
        ) as connection:
            assert "OpenSSH_9.9-new" in connection.get_extra_info("server_version")
    finally:
        await runtime.stop()
        queue.close()


async def test_profile_runtime_keeps_real_listener_when_candidate_port_is_occupied(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "profile-runtime-occupied.sqlite3")
    active_port = _free_port()
    occupied_port = _free_port()
    blocker = await asyncio.start_server(
        lambda _reader, _writer: None, "127.0.0.1", occupied_port
    )

    def build(configuration: dict[str, Any]) -> list[LowSshAgent]:
        return [
            LowSshAgent(
                trap_id=uuid4(), host="127.0.0.1", port=port,
                banner=configuration["banner"], queue=queue,
            )
            for port in configuration["ports"]
        ]

    runtime = ProfileRuntime(build)
    await runtime.start({
        "profile_version": 1,
        "banner": "SSH-2.0-last-good",
        "ports": [active_port],
    })
    try:
        async def occupied_configuration() -> dict[str, Any]:
            return {
                "profile_version": 2,
                "banner": "SSH-2.0-candidate",
                "ports": [active_port, occupied_port],
            }

        with pytest.raises(ProfileApplyError):
            await runtime.refresh(occupied_configuration)

        reader, writer = await asyncio.open_connection("127.0.0.1", active_port)
        assert await reader.readline() == b"SSH-2.0-last-good\r\n"
        assert runtime.active_profile_version == 1
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
        blocker.close()
        await blocker.wait_closed()
        queue.close()


def _free_port() -> int:
    import socket

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])

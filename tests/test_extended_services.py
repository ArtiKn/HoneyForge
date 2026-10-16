import asyncio
import base64
import hashlib
from uuid import uuid4

import asyncssh
import pytest
from pydantic import ValidationError

from agent.low.honeyforge_low import EventQueue, LowHttpAgent, LowSshAgent, LowUdpAgent
from agent.low.profile_runtime import ProfileRuntime, ProfileApplyError
from agent.medium.fake_fs import FakeShell
from agent.medium.http_service import MediumHttpService
from agent.medium.main import MediumSshService
from agent.medium.mysql_service import MediumMySqlService
from center.api.schemas.security_event import CapturedPayload, SecurityEventSchema
from center.api.schemas.trap_profile import TrapProfileCreate
from honeyforge_common.telemetry import captured_binary
from tests.support import mysql_login, mysql_query, write_packet


def test_fake_fs_navigation_isolated_and_never_reads_host(tmp_path):
    (tmp_path / 'secret').write_text('REAL HOST SECRET')
    first, second = FakeShell('admin'), FakeShell('admin')
    assert first.execute('pwd')[0] == '/home/admin\r\n$ '
    assert 'README.txt' in first.execute('ls')[0]
    first.execute('cd ../../etc')
    assert first.execute('pwd')[0] == '/etc\r\n$ '
    assert 'Ubuntu' in first.execute('cat os-release')[0]
    assert 'No such file' in first.execute(f'cat {tmp_path}/secret')[0]
    first.execute('cd /var/www/html')
    assert 'localhost' in first.execute('cat config.php')[0]
    first.execute('cd /does-not-exist')
    assert first.cwd == '/var/www/html'
    assert second.cwd == '/home/admin'
    assert first.execute('touch /tmp/marker')[0].startswith('command not found')
    assert not (tmp_path / 'marker').exists()


@pytest.mark.parametrize('limit', [0, 1, 4096, 1048576])
@pytest.mark.parametrize('enabled', [False, True])
def test_binary_capture_limits_and_contract(limit, enabled):
    raw = b'\x00\xff\xfe' * 30000
    payload = {'kind': 'tcp', **captured_binary(raw, max_bytes=limit, enabled=enabled)}
    CapturedPayload.model_validate(payload)
    decoded = base64.b64decode(payload['data'])
    assert decoded == (raw[:min(limit, 65536)] if enabled else b'')
    assert payload['sha256'] == (hashlib.sha256(raw).hexdigest() if enabled and limit else None)
    assert payload['truncated'] is (len(decoded) < len(raw))
    with pytest.raises(ValidationError):
        CapturedPayload.model_validate({**payload, 'bytes_captured': len(decoded) + 1})


def test_profile_supports_mysql_medium_and_udp_low_with_shared_tcp_port():
    TrapProfileCreate(name='DB', interaction_level='medium', services=[{'protocol': 'mysql', 'internal_port': 3306}])
    TrapProfileCreate(name='Both', interaction_level='low', services=[
        {'protocol': 'udp', 'internal_port': 80}, {'protocol': 'http', 'internal_port': 80}])
    with pytest.raises(ValidationError):
        TrapProfileCreate(name='Invalid', interaction_level='medium', services=[{'protocol': 'udp', 'internal_port': 80}])


@pytest.mark.asyncio
@pytest.mark.parametrize('service_type', [LowHttpAgent, MediumHttpService])
@pytest.mark.parametrize('capture_bodies,capture_credentials', [(True, True), (False, True), (True, False)])
async def test_http_binary_payload_over_real_connection(tmp_path, service_type, capture_bodies, capture_credentials):
    queue = EventQueue(tmp_path / 'http.sqlite3')
    service = service_type(trap_id=uuid4(), host='127.0.0.1', port=0, queue=queue,
        max_payload_bytes=5, capture_http_bodies=capture_bodies, capture_credentials=capture_credentials)
    await service.start()
    body = b'\x00\xffmultipart-payload\x01'
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', service.port)
        writer.write(b'POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n')
        await writer.drain()
        # Fragmented body must be read, rather than silently discarded.
        writer.write(body[:3])
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(body[3:])
        await writer.drain()
        assert (await reader.read()).startswith(b'HTTP/1.1 ')
        writer.close()
        await writer.wait_closed()
        await service.wait_drained()
    finally:
        await service.stop()
    events = queue.pending(limit=20)
    for event in events:
        SecurityEventSchema.model_validate(event)
    capture = next(e['payload'] for e in events if e['event_type'] == 'payload_received')
    assert base64.b64decode(capture['data']) == (body[:5] if capture_bodies and capture_credentials else b'')
    assert capture['bytes_received'] == len(body)
    queue.close()


@pytest.mark.asyncio
async def test_low_ssh_records_binary_banner_request(tmp_path):
    queue = EventQueue(tmp_path / 'ssh.sqlite3')
    service = LowSshAgent(trap_id=uuid4(), host='127.0.0.1', port=0, queue=queue, banner='SSH-2.0-OpenSSH_8.9')
    await service.start()
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', service.port)
        await reader.readline()
        writer.write(b'SSH-2.0-scanner\r\n\x00\xff')
        await writer.drain()
        writer.write_eof()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        await service.wait_drained()
    finally:
        await service.stop()
    events = queue.pending(limit=10)
    capture = next(e for e in events if e['event_type'] == 'payload_received')
    SecurityEventSchema.model_validate(capture)
    assert base64.b64decode(capture['payload']['data']) == b'SSH-2.0-scanner\r\n\x00\xff'
    queue.close()


@pytest.mark.asyncio
async def test_udp_capture_lifecycle_and_no_amplification(tmp_path):
    queue = EventQueue(tmp_path / 'udp.sqlite3')
    service = LowUdpAgent(trap_id=uuid4(), host='127.0.0.1', port=0, queue=queue, banner='Service ready')
    await service.prepare()
    await service.start_accepting()
    loop = asyncio.get_running_loop()
    response = loop.create_future()
    class Client(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not response.done():
                response.set_result(data)
    transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=('127.0.0.1', service.port))
    try:
        transport.sendto(b'ignored before commit')
        await asyncio.sleep(0.02)
        assert queue.pending_count() == 0
        service.commit()
        transport.sendto(b'\x00\xffxx')
        assert await asyncio.wait_for(response, 1) == b'Serv'
        await service.wait_drained()
    finally:
        transport.close()
        await service.stop()
    events = queue.pending(limit=20)
    assert [e['event_type'] for e in events] == ['connection_opened', 'payload_received', 'connection_closed']
    for event in events:
        SecurityEventSchema.model_validate(event)
    assert base64.b64decode(events[1]['payload']['data']) == b'\x00\xffxx'
    assert len({e['attack_session_id'] for e in events}) == 1
    queue.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('capture', [True, False])
async def test_mysql_native_auth_queries_and_no_host_execution(tmp_path, capture):
    queue = EventQueue(tmp_path / 'mysql.sqlite3')
    service = MediumMySqlService(trap_id=uuid4(), host='127.0.0.1', port=0, queue=queue,
        accepted_credentials=[{'username': 'admin', 'password': 'secret', 'service': 'mysql'}],
        capture_credentials=capture, capture_commands=capture)
    await service.start()
    try:
        reader, writer, denied = await mysql_login(service.port, password='wrong')
        assert denied[0] == 255
        writer.close()
        await writer.wait_closed()
        reader, writer, ok = await mysql_login(service.port)
        assert ok[0] == 0
        assert await mysql_query(reader, writer, 'SELECT 1') == [b'\x011']
        assert b'app' in b''.join(await mysql_query(reader, writer, 'SHOW DATABASES'))
        assert b'users' in b''.join(await mysql_query(reader, writer, 'SHOW TABLES'))
        assert b'admin@example.test' in b''.join(await mysql_query(reader, writer, 'SELECT * FROM users LIMIT 1'))
        assert (await mysql_query(reader, writer, "SELECT LOAD_FILE('/etc/passwd')"))[0][0] == 255
        assert (await mysql_query(reader, writer, "DROP TABLE users"))[0][0] == 255
        assert b'admin@example.test' in b''.join(await mysql_query(reader, writer, 'SELECT email FROM users'))
        await write_packet(writer, b'\x01')
        await reader.read()
        writer.close()
        await writer.wait_closed()
        await service.wait_drained()
    finally:
        await service.stop()
    events = queue.pending(limit=100)
    for event in events:
        SecurityEventSchema.model_validate(event)
    attempts = [e['payload'] for e in events if e['event_type'] == 'authentication_attempt']
    assert [p['accepted'] for p in attempts] == [False, True]
    assert all(p['password'] == ('<challenge-response>' if capture else '<redacted>') for p in attempts)
    queries = [e['payload'] for e in events if e['event_type'] == 'database_query']
    assert len(queries) == 7
    assert queries[4]['succeeded'] is False
    if not capture:
        assert all(p['query'] == '<redacted>' for p in queries)
        assert all(p['auth_response'] == p['auth_challenge'] == '<redacted>' for p in attempts)
    else:
        assert all(len(p['auth_challenge']) == len(p['auth_response']) == 40 for p in attempts)
    queue.close()


@pytest.mark.asyncio
async def test_ssh_fake_fs_state_over_real_connection(tmp_path):
    queue = EventQueue(tmp_path / 'fs.sqlite3')
    service = MediumSshService(trap_id=uuid4(), host='127.0.0.1', port=0, queue=queue)
    await service.start()
    try:
        async with asyncssh.connect('127.0.0.1', port=service.port, username='admin', password='x', known_hosts=None) as connection:
            process = await connection.create_process()
            await process.stdout.readuntil('$ ')
            process.stdin.write('cd /etc\npwd\ncat hostname\n')
            await process.stdout.readuntil('$ ')
            assert '/etc' in await process.stdout.readuntil('$ ')
            assert 'web01' in await process.stdout.readuntil('$ ')
            other = await connection.create_process()
            await other.stdout.readuntil('$ ')
            other.stdin.write('pwd\n')
            assert '/home/admin' in await other.stdout.readuntil('$ ')
            process.stdin.write('exit\n')
            other.stdin.write('exit\n')
            await process.wait()
            await other.wait()
    finally:
        await service.stop()
    events = queue.pending(limit=50)
    for event in events:
        SecurityEventSchema.model_validate(event)
    commands = [e['payload'] for e in events if e['event_type'] == 'command_entered']
    assert commands[0]['cwd'] == '/home/admin'
    assert commands[1]['cwd'] == '/etc'
    assert commands[3]['cwd'] == '/home/admin'
    queue.close()


@pytest.mark.asyncio
async def test_udp_runtime_rolls_back_failed_profile_and_can_disable(tmp_path):
    queue = EventQueue(tmp_path / 'runtime.sqlite3')
    built = []
    def services(config):
        candidate = [LowUdpAgent(trap_id=uuid4(), host='127.0.0.1', port=config['port'], queue=queue)]
        if config.get('fail'):
            candidate.append(LowUdpAgent(trap_id=uuid4(), host='127.0.0.1', port=config['port'], queue=queue))
        built.extend(candidate)
        return candidate
    runtime = ProfileRuntime(services)
    await runtime.start({'profile_version': 1, 'port': 0})
    port = built[0].port
    try:
        with pytest.raises(ProfileApplyError):
            await runtime.apply({'profile_version': 2, 'port': port, 'fail': True})
        assert runtime.active_profile_version == 1
        assert built[0]._transport is not None
        await runtime.apply({'profile_version': 1, 'port': 0, 'enabled': False})
        assert runtime.enabled is False and built[0]._transport is None
        await runtime.apply({'profile_version': 1, 'port': 0, 'enabled': True})
        assert runtime.enabled is True
    finally:
        await runtime.stop()
        queue.close()


@pytest.mark.asyncio
async def test_mysql_rejects_oversized_packet_before_reading_body(tmp_path):
    queue = EventQueue(tmp_path / 'oversized.sqlite3')
    service = MediumMySqlService(trap_id=uuid4(), host='127.0.0.1', port=0, queue=queue, max_input_bytes=64)
    await service.start()
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', service.port)
        from tests.support import read_packet
        await read_packet(reader)
        writer.write((65535).to_bytes(3, 'little') + b'\x01')
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 1) == b''
        writer.close()
        await writer.wait_closed()
        await service.wait_drained()
    finally:
        await service.stop()
        queue.close()

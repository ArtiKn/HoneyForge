"""Check actual Agent output against the strict wire contract for all settings."""
from uuid import uuid4
from urllib.parse import urlencode

import pytest

from agent.low.honeyforge_low import EventQueue
from agent.medium.http_service import MediumHttpService
from agent.medium.main import MediumSshService, _AttackConnection
from center.api.schemas.security_event import SecurityEventSchema
from honeyforge_common.telemetry import captured_text


@pytest.mark.parametrize('capture_credentials', [False, True])
@pytest.mark.parametrize('capture_http_bodies', [False, True])
@pytest.mark.parametrize('limit', [0, 1, 7, 4096, 1048576])
def test_http_login_events_always_satisfy_wire_contract(
    tmp_path, capture_credentials, capture_http_bodies, limit,
):
    queue = EventQueue(tmp_path / 'http.sqlite3')
    service = MediumHttpService(
        trap_id=uuid4(), host='127.0.0.1', port=8080, queue=queue,
        capture_credentials=capture_credentials,
        capture_http_bodies=capture_http_bodies, max_payload_bytes=limit,
    )
    username, password = 'оператор' * 100, '🔑секрет' * 300
    service._route('POST', '/login', {}, urlencode({
        'username': username, 'password': password,
    }).encode(), str(uuid4()), '192.0.2.1', 12345)
    event = queue.pending(limit=1)[0]
    SecurityEventSchema.model_validate(event)
    payload = event['payload']
    assert payload['accepted'] is True
    if not capture_credentials or limit == 0:
        assert payload['username'] == payload['password'] == '<redacted>'
    else:
        assert len(payload['username'].encode()) <= limit or payload['username'] == 'unknown'
        assert len(payload['password'].encode()) <= limit
        assert username.startswith(payload['username']) or payload['username'] == 'unknown'
        assert password.startswith(payload['password'])
    queue.close()


def test_http_authentication_uses_full_credentials_not_truncated_log_values(tmp_path):
    queue = EventQueue(tmp_path / 'http.sqlite3')
    service = MediumHttpService(
        trap_id=uuid4(), host='127.0.0.1', port=8080, queue=queue,
        accepted_credentials=[{'username': 'u' * 256, 'password': 'p' * 1024}],
        max_payload_bytes=1,
    )
    service._route('POST', '/login', {},
        ('username=' + 'u' * 257 + '&password=' + 'p' * 1025).encode(),
        str(uuid4()), '192.0.2.1', 12345)
    event = queue.pending(limit=1)[0]
    SecurityEventSchema.model_validate(event)
    assert event['payload'] == {'username': 'u', 'password': 'p', 'accepted': False}
    queue.close()


@pytest.mark.parametrize('limit', [0, 1, 7, 4096, 1048576])
@pytest.mark.parametrize('capture_credentials', [False, True])
@pytest.mark.parametrize('capture_commands', [False, True])
def test_ssh_captured_text_obeys_both_byte_and_wire_limits(
    tmp_path, limit, capture_credentials, capture_commands,
):
    queue = EventQueue(tmp_path / 'ssh.sqlite3')
    service = MediumSshService(
        trap_id=uuid4(), host='127.0.0.1', port=2222, queue=queue,
        max_payload_bytes=limit, capture_credentials=capture_credentials, capture_commands=capture_commands,
    )
    values = {
        'username': service.recorded_username('я' * 3000),
        'password': service.recorded_password('🔑' * 3000),
        'command': service.recorded_command('команда' * 3000),
    }
    for name, value in values.items():
        enabled = capture_commands if name == 'command' else capture_credentials
        if not enabled or limit == 0:
            assert value == '<redacted>'
        elif value != 'unknown':
            assert len(value.encode()) <= limit
        assert '\ufffd' not in value
    attack = _AttackConnection(str(uuid4()), '192.0.2.1', 12345)
    service.enqueue(attack, 'authentication_attempt', {
        'username': values['username'], 'password': values['password'], 'accepted': False,
    })
    service.enqueue(attack, 'command_entered', {'command': values['command']})
    for event in queue.pending(limit=2):
        SecurityEventSchema.model_validate(event)
    queue.close()


def test_utf8_capture_never_splits_a_codepoint():
    assert captured_text('я🔑x', enabled=True, max_bytes=5, max_chars=100) == 'я'
    assert captured_text('я🔑x', enabled=True, max_bytes=6, max_chars=100) == 'я🔑'

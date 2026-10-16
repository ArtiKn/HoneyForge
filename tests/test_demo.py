from pathlib import Path

from deploy.scripts.demo import (
    DEMO_PORTS,
    deterministic_targets,
    ensure_demo_env,
    validate_local_host,
)


def test_demo_env_fills_missing_secrets_and_preserves_existing_values(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPERATOR_USERNAME=reviewer\nCENTER_HTTPS_PORT=9443\n")

    ensure_demo_env(env_file)

    values = dict(
        line.split("=", 1)
        for line in env_file.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    assert values["OPERATOR_USERNAME"] == "reviewer"
    assert values["CENTER_HTTPS_PORT"] == "9443"
    assert len(values["JWT_SECRET"]) >= 32
    assert len(values["OPERATOR_PASSWORD"]) >= 12
    assert values["CENTER_HTTPS_PORT"] != "443"
    assert values["LOW_SSH_PORT"] == "2222"
    assert values["MEDIUM_HTTP_PORT"] == "8081"


def test_demo_env_is_idempotent(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    ensure_demo_env(env_file)
    first = env_file.read_text()
    ensure_demo_env(env_file)
    assert env_file.read_text() == first


def test_deterministic_targets_are_local_demo_ports_only() -> None:
    targets = deterministic_targets("127.0.0.1")

    assert targets == {
        "ssh_low": ("127.0.0.1", DEMO_PORTS["low_ssh"]),
        "http_low": ("127.0.0.1", DEMO_PORTS["low_http"]),
        "mysql_low": ("127.0.0.1", DEMO_PORTS["low_mysql"]),
        "ssh_medium": ("127.0.0.1", DEMO_PORTS["medium_ssh"]),
        "http_medium": ("127.0.0.1", DEMO_PORTS["medium_http"]),
        "mysql_medium": ("127.0.0.1", DEMO_PORTS["medium_mysql"]),
        "udp_low": ("127.0.0.1", DEMO_PORTS["low_udp"]),
    }
    assert all(host in {"127.0.0.1", "localhost"} for host, _ in targets.values())


def test_demo_attack_rejects_non_local_target() -> None:
    for host in ("example.com", "192.0.2.10", "0.0.0.0"):
        try:
            validate_local_host(host)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted non-local target {host}")


def test_acceptance_package_exists() -> None:
    root = Path(__file__).parents[1]
    assert (root / "docs" / "acceptance_report.md").is_file()
    assert (root / "docs" / "presentation.md").is_file()
    assert (root / "docs" / "screenshots" / "dashboard.svg").is_file()
    assert (root / "docs" / "screenshots" / "dashboard.png").is_file()
    assert (root / "docs" / "screenshots" / "login.png").is_file()
    makefile = (root / "Makefile").read_text()
    assert "demo:" in makefile
    assert "demo-attack:" in makefile
    assert "demo-smoke:" in makefile


def test_seed_adds_new_services_to_existing_demo_profiles(tmp_path, monkeypatch):
    from deploy.scripts import demo
    import copy

    monkeypatch.setattr(demo, "ROOT", tmp_path)
    monkeypatch.setattr(demo.ssl, "create_default_context", lambda **kwargs: object())
    monkeypatch.setattr(demo, "build_opener", lambda *args: object())
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    for name in ("low_trap_secret", "medium_trap_secret"):
        (secret_dir / name).write_text("existing-secret")
    profiles = [{
        "id": level, "name": f"Demo {level.title()}", "version": 7,
        "interaction_level": level,
        "services": [{"protocol": "ssh", "internal_port": 22}],
        "decoy_credentials": [], "logging": {"max_payload_bytes": 17}, "masking": {},
    } for level in ("low", "medium")]
    updates = []
    def request(opener, url, *, method="GET", payload=None, if_match=None):
        if url.endswith('/auth/login'):
            return {}
        if url.endswith('/trap-profiles'):
            return copy.deepcopy(profiles)
        if '/trap-profiles/' in url:
            assert method == 'PUT' and if_match == 7
            assert payload['logging'] == {'max_payload_bytes': 17}
            updates.append(payload)
            return {**payload, 'id': url.rsplit('/', 1)[1], 'version': 8}
        if url.endswith('/traps'):
            return [{'id': p['id'], 'name': p['name'], 'enabled': True,
                     'status': 'online', 'is_archived': False} for p in profiles]
        raise AssertionError(url)
    monkeypatch.setattr(demo, '_json_request', request)
    demo.seed_demo('https://test', tmp_path / 'ca.crt', {'OPERATOR_USERNAME': 'operator', 'OPERATOR_PASSWORD': 'test'})
    assert {s['protocol'] for s in updates[0]['services']} == {'ssh', 'http', 'mysql', 'udp'}
    assert {s['protocol'] for s in updates[1]['services']} == {'ssh', 'http', 'mysql'}


def test_seed_migrates_the_legacy_demo_masking_and_keeps_operator_edits(
    tmp_path, monkeypatch
):
    from deploy.scripts import demo
    import copy

    monkeypatch.setattr(demo, "ROOT", tmp_path)
    monkeypatch.setattr(demo.ssl, "create_default_context", lambda **kwargs: object())
    monkeypatch.setattr(demo, "build_opener", lambda *args: object())
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    for name in ("low_trap_secret", "medium_trap_secret"):
        (secret_dir / name).write_text("existing-secret")
    profiles = [
        {
            "id": "low", "name": "Demo Low", "version": 3, "interaction_level": "low",
            "services": [{"protocol": "ssh", "internal_port": 22},
                         {"protocol": "http", "internal_port": 80},
                         {"protocol": "mysql", "internal_port": 3306},
                         {"protocol": "udp", "internal_port": 9999}],
            "decoy_credentials": [], "logging": {"max_payload_bytes": 4096},
            "masking": {"beacon_interval_seconds": 300, "beacon_jitter_seconds": 45},
        },
        {
            "id": "medium", "name": "Demo Medium", "version": 4, "interaction_level": "medium",
            "services": [{"protocol": "ssh", "internal_port": 22},
                         {"protocol": "http", "internal_port": 80},
                         {"protocol": "mysql", "internal_port": 3306}],
            "decoy_credentials": [], "logging": {"max_payload_bytes": 4096},
            "masking": {"beacon_interval_seconds": 900, "beacon_jitter_seconds": 60},
        },
    ]
    updates = []

    def request(opener, url, *, method="GET", payload=None, if_match=None):
        if url.endswith('/auth/login'):
            return {}
        if url.endswith('/trap-profiles'):
            return copy.deepcopy(profiles)
        if '/trap-profiles/' in url:
            updates.append(payload)
            return {**payload, 'id': url.rsplit('/', 1)[1], 'version': if_match + 1}
        if url.endswith('/traps'):
            return [{"id": p["id"], "name": p["name"], "enabled": True,
                     "status": "online", "is_archived": False} for p in profiles]
        raise AssertionError(url)

    monkeypatch.setattr(demo, "_json_request", request)
    demo.seed_demo(
        'https://test', tmp_path / 'ca.crt',
        {'OPERATOR_USERNAME': 'operator', 'OPERATOR_PASSWORD': 'test'},
    )

    assert len(updates) == 1, "only the legacy demo profile is reconciled"
    migrated = updates[0]['masking']
    assert migrated['beacon_interval_seconds'] == 5
    assert migrated['beacon_jitter_seconds'] == 2
    assert migrated['user_agent'].startswith('Mozilla/5.0')

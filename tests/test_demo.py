import json
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

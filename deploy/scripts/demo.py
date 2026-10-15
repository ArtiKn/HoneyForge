"""Repeatable local MVP demo orchestration and deterministic acceptance probes."""

from __future__ import annotations

import argparse
import json
import secrets
import ssl
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener, urlopen
from uuid import uuid4

ROOT = Path(__file__).parents[2]
ENV_FILE = ROOT / ".env"
DEMO_PORTS = {
    "control_center": 8443,
    "low_ssh": 2222,
    "low_http": 8080,
    "low_mysql": 33060,
    "medium_ssh": 2223,
    "medium_http": 8081,
}


def _read_env(path: Path) -> tuple[list[str], dict[str, str]]:
    lines = path.read_text().splitlines() if path.exists() else []
    values: dict[str, str] = {}
    for line in lines:
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return lines, values


def ensure_demo_env(path: Path = ENV_FILE) -> dict[str, str]:
    """Create or repair only demo defaults, preserving explicit operator choices."""

    lines, values = _read_env(path)
    old_db_password = values.get("POSTGRES_PASSWORD", "")
    if not old_db_password or old_db_password in {"change-me-in-production", "change-me"}:
        values["POSTGRES_PASSWORD"] = secrets.token_urlsafe(24)
    if not values.get("JWT_SECRET") or len(values["JWT_SECRET"]) < 32:
        values["JWT_SECRET"] = secrets.token_urlsafe(32)
    if not values.get("OPERATOR_PASSWORD") or len(values["OPERATOR_PASSWORD"]) < 12:
        values["OPERATOR_PASSWORD"] = secrets.token_urlsafe(16)
    values.setdefault("POSTGRES_USER", "honeyforge")
    values.setdefault("POSTGRES_DB", "honeyforge")
    values["DATABASE_URL"] = (
        f"postgresql+asyncpg://{values['POSTGRES_USER']}:{values['POSTGRES_PASSWORD']}"
        f"@postgres:5432/{values['POSTGRES_DB']}"
    )
    if values.get("CENTER_HTTPS_PORT") in {None, "", "443"}:
        values["CENTER_HTTPS_PORT"] = str(DEMO_PORTS["control_center"])
    values.setdefault("CENTER_HTTP_PORT", "80")
    values.setdefault("CENTER_DOMAIN", "localhost")
    if values.get("CENTER_URL") in {None, "", "https://localhost", "https://localhost:443"}:
        values["CENTER_URL"] = f"https://localhost:{values['CENTER_HTTPS_PORT']}"
    values.setdefault("OPERATOR_USERNAME", "operator")
    if values.get("LOW_TRAP_SECRET_FILE", "").startswith("./secrets/"):
        values["LOW_TRAP_SECRET_FILE"] = values["LOW_TRAP_SECRET_FILE"].replace(
            "./secrets/", "../secrets/", 1
        )
    values.setdefault("LOW_TRAP_SECRET_FILE", "../secrets/low_trap_secret")
    if values.get("MEDIUM_TRAP_SECRET_FILE", "").startswith("./secrets/"):
        values["MEDIUM_TRAP_SECRET_FILE"] = values["MEDIUM_TRAP_SECRET_FILE"].replace(
            "./secrets/", "../secrets/", 1
        )
    values.setdefault("MEDIUM_TRAP_SECRET_FILE", "../secrets/medium_trap_secret")
    values.setdefault("LOW_SSH_PORT", str(DEMO_PORTS["low_ssh"]))
    values.setdefault("MEDIUM_SSH_PORT", str(DEMO_PORTS["medium_ssh"]))
    values.setdefault("MEDIUM_HTTP_PORT", str(DEMO_PORTS["medium_http"]))
    values.setdefault("LOW_HTTP_PORT", str(DEMO_PORTS["low_http"]))
    values.setdefault("LOW_MYSQL_PORT", str(DEMO_PORTS["low_mysql"]))
    values.setdefault("AGENT_CENTER_URL", "https://assets.cdn-static.example:8443")
    values["HOST_SECRET_GID"] = str(path.parent.stat().st_gid)

    existing_keys = set()
    output: list[str] = []
    for line in lines:
        if line and not line.startswith("#") and "=" in line:
            key = line.split("=", 1)[0]
            existing_keys.add(key)
            output.append(f"{key}={values[key]}")
        else:
            output.append(line)
    for key, value in values.items():
        if key not in existing_keys:
            output.append(f"{key}={value}")
    path.write_text("\n".join(output).rstrip() + "\n")
    path.chmod(0o600)
    return values


def deterministic_targets(host: str = "127.0.0.1") -> dict[str, tuple[str, int]]:
    validate_local_host(host)
    return {
        "ssh_low": (host, DEMO_PORTS["low_ssh"]),
        "http_low": (host, DEMO_PORTS["low_http"]),
        "mysql_low": (host, DEMO_PORTS["low_mysql"]),
        "ssh_medium": (host, DEMO_PORTS["medium_ssh"]),
        "http_medium": (host, DEMO_PORTS["medium_http"]),
    }


def validate_local_host(host: str) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("demo attacks are restricted to the local host")


def wait_for_targets(
    targets: dict[str, tuple[str, int]], timeout: float = 30
) -> None:
    deadline = time.monotonic() + timeout
    pending = dict(targets)
    while pending and time.monotonic() < deadline:
        for name, address in list(pending.items()):
            try:
                with socket.create_connection(address, timeout=1):
                    pending.pop(name)
            except OSError:
                pass
        if pending:
            time.sleep(0.5)
    if pending:
        raise TimeoutError(f"Demo targets did not start: {', '.join(sorted(pending))}")


def run_demo_attack(host: str = "127.0.0.1", timeout: float = 3.0) -> dict[str, str]:
    """Generate one representative interaction per exposed local demo service."""

    targets = deterministic_targets(host)
    wait_for_targets(targets)
    results: dict[str, str] = {}
    with socket.create_connection(targets["ssh_low"], timeout=timeout) as connection:
        results["ssh_low"] = connection.recv(256).decode(errors="replace").strip()
        connection.sendall(b"HoneyForge demo\n")
    with socket.create_connection(targets["http_low"], timeout=timeout) as connection:
        connection.sendall(b"GET /demo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        results["http_low"] = connection.recv(512).decode(errors="replace").splitlines()[0]
    with socket.create_connection(targets["mysql_low"], timeout=timeout) as connection:
        results["mysql_low"] = connection.recv(512).decode(errors="replace").strip()
    with socket.create_connection(targets["ssh_medium"], timeout=timeout) as connection:
        results["ssh_medium"] = connection.recv(256).decode(errors="replace").strip()
    with socket.create_connection(targets["http_medium"], timeout=timeout) as connection:
        connection.sendall(b"GET /demo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        results["http_medium"] = connection.recv(512).decode(errors="replace").splitlines()[0]
    return results


def _read_websocket_frame(connection: ssl.SSLSocket) -> dict[str, Any]:
    first = connection.recv(2)
    if len(first) != 2:
        raise RuntimeError("WebSocket closed before Security Event broadcast")
    length = first[1] & 0x7F
    if length == 126:
        length = int.from_bytes(connection.recv(2), "big")
    elif length == 127:
        length = int.from_bytes(connection.recv(8), "big")
    payload = connection.recv(length)
    return json.loads(payload.decode())


def smoke_operator_surface(
    base_url: str,
    ca_file: Path,
    values: dict[str, str],
    trap_secret_file: Path,
    expected_event_ids: list[str] | None = None,
) -> dict[str, bool]:
    """Prove REST catch-up, Operator UI visibility and live Security Event broadcast."""

    context = ssl.create_default_context(cafile=str(ca_file))
    cookie_handler = HTTPCookieProcessor()
    opener = build_opener(cookie_handler, HTTPSHandler(context=context))
    _json_request(
        opener,
        f"{base_url}/api/v1/auth/login",
        method="POST",
        payload={"username": values["OPERATOR_USERNAME"], "password": values["OPERATOR_PASSWORD"]},
    )
    expected_event_ids = expected_event_ids or []
    buffered_events_persisted = _wait_for_rest_security_events(
        opener,
        base_url,
        expected_event_ids,
        trap_id=trap_secret_file.read_text().strip().split(".", 1)[0],
    )
    with opener.open(f"{base_url}/events.html", timeout=10) as response:
        ui = response.read().decode()

    cookie = "; ".join(
        f"{item.name}={item.value}" for item in cookie_handler.cookiejar
    )
    parts = urlsplit(base_url)
    connection = socket.create_connection((parts.hostname or "localhost", parts.port or 443), timeout=10)
    secure = context.wrap_socket(connection, server_hostname=parts.hostname or "localhost")
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    secure.sendall((
        f"GET /ws HTTP/1.1\r\nHost: {parts.hostname}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        f"Cookie: {cookie}\r\n\r\n"
    ).encode())
    handshake = secure.recv(1024)
    if b"101 Switching Protocols" not in handshake:
        raise RuntimeError(
            "Operator WebSocket did not authenticate: "
            + handshake.decode(errors="replace")
        )
    mask = b"demo"
    frame = bytes([0x81, 0x80 | len(mask)]) + b"\x00\x00\x00\x00" + bytes(
        value ^ mask[index % len(mask)] for index, value in enumerate(mask)
    )
    secure.sendall(frame)

    secret = trap_secret_file.read_text().strip()
    trap_id = secret.split(".", 1)[0]
    security_event_id = str(uuid4())
    security_event = {
        "id": security_event_id,
        "schema_version": 1,
        "trap_id": trap_id,
        "attack_session_id": str(uuid4()),
        "event_type": "connection_opened",
        "observed_at": datetime.now(UTC).isoformat(),
        "source_ip": "192.0.2.16",
        "source_port": 49153,
        "target_service": "ssh",
        "target_port": 22,
        "payload": {"banner": "SSH-2.0-HoneyForge-live-smoke"},
    }
    request = Request(
        f"{base_url}/assets/v2/init",
        data=json.dumps({"events": [security_event]}).encode(),
        method="POST",
        headers={
            "Host": "assets.cdn-static.example",
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/javascript",
        },
    )
    with urlopen(request, context=context, timeout=10) as response:
        if security_event_id not in json.loads(response.read())["accepted"]:
            raise RuntimeError("Live smoke Security Event was not persisted")
    secure.settimeout(10)
    broadcast = _read_websocket_frame(secure)
    secure.close()
    live_event_persisted = _wait_for_rest_security_events(
        opener,
        base_url,
        [security_event_id],
        trap_id=trap_id,
    )
    return {
        "buffered_delivery": buffered_events_persisted,
        "rest_catch_up": buffered_events_persisted and live_event_persisted,
        "operator_ui": "Security Events" in ui,
        "websocket": broadcast.get("id") == security_event_id,
    }


def _wait_for_rest_security_events(
    opener: Any,
    base_url: str,
    expected_event_ids: list[str],
    *,
    trap_id: str,
    timeout: float = 30,
) -> bool:
    """Wait until REST exposes every expected Security Event exactly once."""

    if not expected_event_ids:
        return True
    expected = set(expected_event_ids)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        counts = {event_id: 0 for event_id in expected}
        cursor: str | None = None
        while True:
            query = {"trap_id": trap_id, "limit": "500"}
            if cursor:
                query["cursor"] = cursor
            with opener.open(
                f"{base_url}/api/v1/security-events?{urlencode(query)}",
                timeout=10,
            ) as response:
                page = json.loads(response.read())
            for item in page["items"]:
                if item["id"] in counts:
                    counts[item["id"]] += 1
            cursor = page.get("next_cursor")
            if not cursor:
                break
        if all(count == 1 for count in counts.values()):
            return True
        time.sleep(1)
    missing = sorted(event_id for event_id, count in counts.items() if count != 1)
    raise RuntimeError(
        "Security Events were not delivered exactly once through REST: "
        + ", ".join(missing)
    )


def _json_request(opener: Any, url: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Content-Type": "application/json",
        "Origin": url.split("/api/", 1)[0],
    }
    if "/assets/v2/" in url:
        headers["Host"] = "assets.cdn-static.example"
    request = Request(
        url,
        data=body,
        method=method,
        headers=headers,
    )
    with opener.open(request, timeout=15) as response:
        return json.loads(response.read()) if response.status != 204 else None


def wait_ready(base_url: str, ca_file: Path, timeout: float = 180) -> None:
    context = ssl.create_default_context(cafile=str(ca_file))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{base_url}/ready", context=context, timeout=5) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(2)
    raise TimeoutError(f"HoneyForge did not become ready within {timeout:.0f}s")


def seed_demo(base_url: str, ca_file: Path, values: dict[str, str]) -> None:
    context = ssl.create_default_context(cafile=str(ca_file))
    opener = build_opener(HTTPCookieProcessor(), HTTPSHandler(context=context))
    _json_request(opener, f"{base_url}/api/v1/auth/login", method="POST", payload={
        "username": values["OPERATOR_USERNAME"], "password": values["OPERATOR_PASSWORD"]
    })
    trap_profiles = _json_request(opener, f"{base_url}/api/v1/trap-profiles")
    trap_profile_specs = {
        "Demo Low": {"interaction_level": "low", "services": [
            {"protocol": "ssh", "internal_port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1"},
            {"protocol": "http", "internal_port": 80, "banner": "nginx/1.24.0"},
            {"protocol": "mysql", "internal_port": 3306, "banner": "5.7.42-MySQL"},
        ]},
        "Demo Medium": {"interaction_level": "medium", "services": [
            {"protocol": "ssh", "internal_port": 22, "banner": "OpenSSH_8.9p1", "emulator_settings": {"max_attempts": 5, "response_delay_ms": 150}},
            {"protocol": "http", "internal_port": 80, "banner": "nginx/1.24.0"},
        ], "decoy_credentials": [
            {"username": "svc-backup", "password": "Backup!2026"},
            {"username": "admin", "password": "Summer2026!"},
        ], "logging": {
            "capture_credentials": True,
            "capture_commands": True,
            "capture_http_bodies": True,
            "max_payload_bytes": 4096,
        }, "masking": {
            "beacon_interval_seconds": 300,
            "beacon_jitter_seconds": 45,
        }},
    }
    trap_profile_ids: dict[str, str] = {}
    for name, spec in trap_profile_specs.items():
        existing = next((item for item in trap_profiles if item["name"] == name), None)
        trap_profile_ids[name] = existing["id"] if existing else _json_request(
            opener, f"{base_url}/api/v1/trap-profiles", method="POST", payload={"name": name, **spec}
        )["id"]
    traps = _json_request(opener, f"{base_url}/api/v1/traps")
    secret_dir = ROOT / "secrets"
    secret_dir.mkdir(exist_ok=True)
    for name, trap_profile_name, secret_name in (
        ("Demo Low", "Demo Low", "low_trap_secret"),
        ("Demo Medium", "Demo Medium", "medium_trap_secret"),
    ):
        existing = next((item for item in traps if item["name"] == name), None)
        secret_file = secret_dir / secret_name
        if existing:
            if not secret_file.exists():
                if existing["status"] != "provisioning":
                    raise RuntimeError(
                        f"{secret_file} is missing for an online Trap; refusing to rotate credentials"
                    )
                token = _json_request(
                    opener,
                    f"{base_url}/api/v1/traps/{existing['id']}/enrollment-token",
                    method="POST",
                )["enrollment_token"]
                enrolled = _json_request(
                    opener,
                    f"{base_url}/assets/v2/enroll",
                    method="POST",
                    payload={"enrollment_token": token},
                )
                secret_file.write_text(enrolled["trap_secret"] + "\n")
                secret_file.chmod(0o640)
            continue
        created = _json_request(opener, f"{base_url}/api/v1/traps", method="POST", payload={
            "name": name, "trap_profile_id": trap_profile_ids[trap_profile_name], "hostname": name.lower().replace(" ", "-")
        })
        enrolled = _json_request(opener, f"{base_url}/assets/v2/enroll", method="POST", payload={
            "enrollment_token": created["enrollment_token"]
        })
        secret_file.write_text(enrolled["trap_secret"] + "\n")
        secret_file.chmod(0o640)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("env", "seed", "attack", "smoke"))
    parser.add_argument(
        "--expected-event-id",
        action="append",
        default=[],
        help="Security Event UUID that must have drained from the Agent and reached REST",
    )
    args = parser.parse_args()
    values = ensure_demo_env()
    if args.command == "env":
        return
    if args.command == "seed":
        base_url = f"https://localhost:{values['CENTER_HTTPS_PORT']}"
        wait_ready(base_url, ROOT / "deploy/nginx/certs/ca.crt")
        seed_demo(base_url, ROOT / "deploy/nginx/certs/ca.crt", values)
    elif args.command == "attack":
        print(json.dumps(run_demo_attack(), indent=2))
    else:
        from smoke_deployment import probe_deployment

        result = probe_deployment(
            f"https://localhost:{values['CENTER_HTTPS_PORT']}",
            ca_file=ROOT / "deploy/nginx/certs/ca.crt",
            trap_secret_file=ROOT / "secrets/low_trap_secret",
        )
        result.update(
            smoke_operator_surface(
                f"https://localhost:{values['CENTER_HTTPS_PORT']}",
                ROOT / "deploy/nginx/certs/ca.crt",
                values,
                ROOT / "secrets/low_trap_secret",
                args.expected_event_id,
            )
        )
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

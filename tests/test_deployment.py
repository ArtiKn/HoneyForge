import json
import logging
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

from agent.low.honeyforge_low import AgentClient, JsonLogFormatter
from center.logging import SecretSafeJsonFormatter
from deploy.scripts.smoke_deployment import probe_deployment
from tests.support import create_test_certificate


ROOT = Path(__file__).parents[1]


def test_demo_certificate_script_creates_ca_signed_server_certificate(
    tmp_path: Path,
) -> None:
    certificate_dir = tmp_path / "certs"
    environment = os.environ | {
        "CERT_DIR": str(certificate_dir),
        "CERT_SAN": "DNS:localhost,DNS:assets.cdn-static.example,IP:127.0.0.1",
    }

    subprocess.run(
        ["bash", str(ROOT / "deploy/scripts/gen_certs.sh")],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )

    ca_certificate = certificate_dir / "ca.crt"
    server_certificate = certificate_dir / "center.crt"
    assert ca_certificate.is_file()
    assert (certificate_dir / "ca.key").is_file()
    assert server_certificate.is_file()
    assert (certificate_dir / "center.key").is_file()
    subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca_certificate), str(server_certificate)],
        check=True,
        capture_output=True,
        text=True,
    )
    details = subprocess.run(
        ["openssl", "x509", "-in", str(server_certificate), "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "CA:FALSE" in details
    assert "DNS:localhost, DNS:assets.cdn-static.example, IP Address:127.0.0.1" in details


def test_demo_certificate_script_refuses_partial_bundle_without_force(
    tmp_path: Path,
) -> None:
    certificate_dir = tmp_path / "certs"
    environment = os.environ | {"CERT_DIR": str(certificate_dir)}
    command = ["bash", str(ROOT / "deploy/scripts/gen_certs.sh")]

    subprocess.run(command, check=True, env=environment, capture_output=True, text=True)
    original_ca = (certificate_dir / "ca.crt").read_bytes()
    (certificate_dir / "center.crt").unlink()

    result = subprocess.run(command, env=environment, capture_output=True, text=True)

    assert result.returncode != 0
    assert "partial certificate bundle" in result.stderr
    assert (certificate_dir / "ca.crt").read_bytes() == original_ca


def _compose_config(*filenames: str) -> dict:
    compose_files = [
        argument
        for filename in filenames
        for argument in ("-f", str(ROOT / "deploy" / filename))
    ]
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ROOT / ".env.example"),
            *compose_files,
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=os.environ
        | {
            "JWT_SECRET": "deployment-test-jwt-secret-value",
            "OPERATOR_PASSWORD": "deployment-test-password",
        },
    )
    return json.loads(result.stdout)


def test_deployment_manifests_express_runtime_security_boundaries() -> None:
    center = _compose_config("docker-compose.yml")
    honeypots = _compose_config("docker-compose.honeypots.yml")
    demo_honeypots = _compose_config(
        "docker-compose.honeypots.yml", "docker-compose.demo.yml"
    )

    for service in center["services"].values():
        assert "ALL" in service.get("cap_drop", [])
        assert service["deploy"]["resources"]["limits"]
    assert center["services"]["collector"].get("environment", {}) == {}
    assert "POSTGRES_PASSWORD" not in center["services"]["api"]["environment"]
    for name, service in honeypots["services"].items():
        assert service["user"] == "honeyforge-agent"
        assert service["read_only"] is True
        assert "ALL" in service["cap_drop"]
        assert service["deploy"]["resources"]["limits"]
        assert set(service["networks"]) == {"agent_egress_net", "honeypot_exposed"}
        exposed_address = service["networks"]["honeypot_exposed"]["ipv4_address"]
        assert service["environment"]["LISTEN_HOST"] == exposed_address
        assert service["environment"]["CENTER_CA_FILE"] == "/etc/honeyforge/center-ca.crt"
        masked_name = service["environment"]["PROCESS_MASK_NAME"]
        assert masked_name == "syslog-relay"
        assert not any(
            marker in masked_name.lower()
            for marker in ("honey", "agent", "c2", "trap", "decoy")
        )
        assert "extra_hosts" not in service
        writable_targets = {volume["target"] for volume in service["volumes"]}
        assert "/var/lib/honeyforge" in writable_targets
        assert "assets.cdn-static.example=host-gateway" in demo_honeypots[
            "services"
        ][name]["extra_hosts"]
    assert honeypots["networks"]["honeypot_exposed"]["internal"] is True
    assert not honeypots["networks"]["agent_egress_net"].get("internal", False)


def test_nginx_masks_agent_api_and_enforces_proxy_limits() -> None:
    base = (ROOT / "deploy/nginx/nginx.conf").read_text()
    masked = (ROOT / "deploy/nginx/conf.d/honeypot_masking.conf").read_text()

    assert "limit_req_zone" in base
    assert "limit_conn_zone" in base
    assert "location /assets/v2/" in masked
    assert "proxy_pass http://api:8000/assets/v2/;" in masked
    assert "proxy_set_header X-Forwarded-For   $remote_addr;" in masked
    assert "limit_req" in masked
    assert "limit_conn" in masked
    assert "client_max_body_size" in masked


def test_structured_logs_redact_credentials() -> None:
    secrets = [
        "Bearer trap-secret-value",
        "enrollment_token=one-time-token",
        "trap_secret: rotated-secret",
        "jwt=eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "password=operator-password",
        'password="quoted-operator-password"',
        '{"trap_secret":"json-secret"}',
    ]
    record = logging.LogRecord(
        "honeyforge",
        logging.ERROR,
        __file__,
        1,
        "request failed: %s",
        (" ".join(secrets),),
        None,
    )

    for formatter in (JsonLogFormatter(), SecretSafeJsonFormatter()):
        rendered = formatter.format(record)
        payload = json.loads(rendered)
        assert payload["message"].count("[REDACTED]") >= len(secrets)
        for secret in (
            "trap-secret-value",
            "one-time-token",
            "rotated-secret",
            "eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "operator-password",
            "quoted-operator-password",
            "json-secret",
        ):
            assert secret not in rendered


def test_agent_tls_cannot_disable_certificate_or_hostname_verification() -> None:
    public_ca_client = AgentClient("https://center.example", "trap-secret")

    assert public_ca_client.ssl_context.verify_mode is ssl.CERT_REQUIRED
    assert public_ca_client.ssl_context.check_hostname is True


def test_topology_probe_checks_readiness_and_delivers_security_event(
    tmp_path: Path,
) -> None:
    certificate, private_key = create_test_certificate(tmp_path)
    trap_id = uuid4()
    trap_secret = f"{trap_id}.deployment-secret"
    secret_file = tmp_path / "trap-secret"
    secret_file.write_text(trap_secret)
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == "/ready"
            body = b'{"status":"ready"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            assert self.path == "/assets/v2/init"
            assert self.headers["Authorization"] == f"Bearer {trap_secret}"
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.extend(payload["events"])
            body = json.dumps({"accepted": [payload["events"][0]["id"]]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = probe_deployment(
            f"https://127.0.0.1:{server.server_port}",
            ca_file=certificate,
            trap_secret_file=secret_file,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result == {"readiness": "ready", "accepted_events": 1}
    assert len(received) == 1
    assert received[0]["trap_id"] == str(trap_id)
    assert received[0]["event_type"] == "connection_opened"

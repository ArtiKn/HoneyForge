#!/usr/bin/env python3
import argparse
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from uuid import UUID, uuid4


def probe_deployment(
    center_url: str,
    *,
    ca_file: Path | None,
    trap_secret_file: Path,
) -> dict[str, Any]:
    """Check readiness and persist one synthetic Security Event over verified TLS."""

    if not center_url.startswith("https://"):
        raise ValueError("deployment probe requires HTTPS")
    secret = trap_secret_file.read_text(encoding="utf-8").strip()
    trap_id = UUID(secret.split(".", 1)[0])
    context = ssl.create_default_context(cafile=ca_file)
    base_url = center_url.rstrip("/")

    readiness_response = urlopen(
        f"{base_url}/ready", context=context, timeout=10
    )
    readiness = json.loads(readiness_response.read())["status"]
    if readiness != "ready":
        raise RuntimeError(f"Control Center is not ready: {readiness}")

    event_id = uuid4()
    event = {
        "id": str(event_id),
        "schema_version": 1,
        "trap_id": str(trap_id),
        "attack_session_id": str(uuid4()),
        "event_type": "connection_opened",
        "observed_at": datetime.now(UTC).isoformat(),
        "source_ip": "192.0.2.15",
        "source_port": 49152,
        "target_service": "ssh",
        "target_port": 22,
        "payload": {"banner": "SSH-2.0-HoneyForge-deployment-probe"},
    }
    request = Request(
        f"{base_url}/assets/v2/init",
        data=json.dumps({"events": [event]}, separators=(",", ":")).encode(),
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/javascript",
        },
        method="POST",
    )
    response = urlopen(request, context=context, timeout=10)
    accepted = json.loads(response.read())["accepted"]
    if accepted != [str(event_id)]:
        raise RuntimeError("Control Center did not acknowledge the probe event")
    return {"readiness": readiness, "accepted_events": 1}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify HoneyForge readiness and Security Event delivery"
    )
    parser.add_argument("--center-url", required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--trap-secret-file", type=Path, required=True)
    arguments = parser.parse_args()
    result = probe_deployment(
        arguments.center_url,
        ca_file=arguments.ca_file,
        trap_secret_file=arguments.trap_secret_file,
    )
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()

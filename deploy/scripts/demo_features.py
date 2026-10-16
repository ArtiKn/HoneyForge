"""Feature-by-feature demonstrations against a running Control Center.

Each function is a self-contained, read-mostly scenario that prints what a judge
can see and returns the facts it observed, so ``make demo-tour`` can chain them.
The module only uses the standard library: it runs inside a throwaway container
on the host network, exactly like ``demo.py``.
"""

from __future__ import annotations

import csv
import io
import json
import ssl
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

ROOT = Path(__file__).parents[2]
CA_FILE = ROOT / "deploy/nginx/certs/ca.crt"

# Vocabulary that would reveal the platform if an attacker ever read the artifact.
PLATFORM_MARKERS = (
    "honeyforge",
    "honeypot",
    "honey",
    "приманк",
    "mask-4",
    "mask-5",
    "mask-6",
    "trap-node",
    "c2-beacon",
)


def heading(title: str) -> None:
    print(f"\n\033[1m── {title} {'─' * max(4, 58 - len(title))}\033[0m")


def line(text: str) -> None:
    print(f"  {text}")


@contextmanager
def operator_session(
    base_url: str,
    ca_file: Path,
    username: str,
    password: str,
) -> Iterator[Any]:
    """Yield an authenticated opener for *username* against the center."""

    context = ssl.create_default_context(cafile=str(ca_file))
    opener = build_opener(
        HTTPCookieProcessor(CookieJar()), HTTPSHandler(context=context)
    )
    request = Request(
        f"{base_url}/api/v1/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Origin": base_url,
        },
    )
    with opener.open(request, timeout=15):
        pass
    yield opener


def call(
    opener: Any,
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    """Perform a request and return ``(status, parsed body)`` without raising."""

    request = Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Origin": url.split("/api/", 1)[0],
            **(headers or {}),
        },
    )
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except HTTPError as error:
        body = error.read()
        try:
            return error.code, json.loads(body) if body else None
        except json.JSONDecodeError:
            return error.code, body.decode(errors="replace")


def _short(value: Any, limit: int = 38) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def demo_status(base_url: str, ca_file: Path, values: dict[str, str]) -> dict[str, Any]:
    """Show the fleet: Traps with their status and the Trap Profiles behind them."""

    heading("Парк ловушек и профили (FR-C1, FR-C2)")
    with operator_session(
        base_url, ca_file, values["OPERATOR_USERNAME"], values["OPERATOR_PASSWORD"]
    ) as admin:
        _, traps = call(admin, f"{base_url}/api/v1/traps")
        _, profiles = call(admin, f"{base_url}/api/v1/trap-profiles")
        _, events = call(admin, f"{base_url}/api/v1/security-events?limit=1")

    names = {profile["id"]: f"{profile['name']} v{profile['version']}" for profile in profiles}
    line(f"{'ЛОВУШКА':<16}{'ПРОФИЛЬ':<28}{'СТАТУС':<14}{'ПОСЛЕДНИЙ КОНТАКТ':<22}ВКЛ")
    for trap in traps:
        line(
            f"{_short(trap['name'], 16):<16}"
            f"{_short(names.get(trap['trap_profile_id'], '—'), 28):<28}"
            f"{_short(trap.get('display_status') or trap['status'], 14):<14}"
            f"{_short(trap.get('last_seen_at') or '—', 22):<22}"
            f"{'да' if trap['enabled'] else 'нет'}"
        )
    counts: dict[str, int] = {}
    for trap in traps:
        state = trap.get("display_status") or trap["status"]
        counts[state] = counts.get(state, 0) + 1
    newest = (events or {}).get("items", [{}])[0] if isinstance(events, dict) else {}
    line("")
    line(f"Профилей: {len(profiles)} · ловушек: {len(traps)} · по статусам: {counts}")
    if newest.get("received_at"):
        line(f"Последнее событие в центре: {newest['received_at']} ({newest.get('event_type')})")
    return {"traps": len(traps), "profiles": len(profiles), "statuses": counts}


def demo_export(
    base_url: str,
    ca_file: Path,
    values: dict[str, str],
    *,
    filters: dict[str, Any] | None = None,
    output: Path | None = None,
    rows_preview: int = 5,
) -> dict[str, Any]:
    """Download the IoC CSV of the current investigation (FR-C7)."""

    heading("Экспорт IoC в CSV (FR-C7)")
    query = urlencode({key: value for key, value in (filters or {}).items() if value})
    url = f"{base_url}/api/v1/security-events/export.csv" + (f"?{query}" if query else "")
    with operator_session(
        base_url, ca_file, values["OPERATOR_USERNAME"], values["OPERATOR_PASSWORD"]
    ) as admin:
        request = Request(url, headers={"Origin": base_url})
        with admin.open(request, timeout=30) as response:
            document = response.read().decode("utf-8")
            disposition = response.headers.get("Content-Disposition", "")
    filename = disposition.split("filename=", 1)[-1].strip('"') if disposition else "export.csv"
    rows = list(csv.DictReader(io.StringIO(document)))
    line(f"Файл: {filename}")
    line(f"Фильтры: {query or 'без фильтров'}")
    line(f"Строк: {len(rows)} · колонок: {len(rows[0]) if rows else 0}")
    if rows:
        interesting = ["received_at", "trap_name", "event_type", "source_ip", "username", "command"]
        line(" | ".join(interesting))
        for row in rows[:rows_preview]:
            line(" | ".join(_short(row.get(column, ""), 26) for column in interesting))
        if len(rows) > rows_preview:
            line(f"… и ещё {len(rows) - rows_preview}")
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document, encoding="utf-8")
        line(f"Сохранено: {output}")
    return {"filename": filename, "rows": len(rows), "output": str(output) if output else None}


def _secret_file_for(trap_name: str) -> Path:
    slug = "medium" if "medium" in trap_name.lower() else "low"
    return ROOT / "secrets" / f"{slug}_trap_secret"


def demo_lifecycle(
    base_url: str,
    ca_file: Path,
    values: dict[str, str],
    *,
    trap_name: str = "Demo Low",
    rejoin_timeout: float = 60,
) -> dict[str, Any]:
    """Walk one Trap through stop → start → revoke → restore and heal it (FR-C2)."""

    heading(f"Жизненный цикл ловушки «{trap_name}» (FR-C2)")
    secret_file = _secret_file_for(trap_name)
    steps: list[dict[str, Any]] = []
    with operator_session(
        base_url, ca_file, values["OPERATOR_USERNAME"], values["OPERATOR_PASSWORD"]
    ) as admin:
        _, traps = call(admin, f"{base_url}/api/v1/traps")
        trap = next((item for item in traps if item["name"] == trap_name), None)
        if trap is None:
            raise SystemExit(f"Ловушка «{trap_name}» не найдена: сделайте `make demo-seed`")
        trap_url = f"{base_url}/api/v1/traps/{trap['id']}"

        def step(action: str) -> dict[str, Any]:
            _, updated = call(admin, f"{trap_url}/{action}", method="POST")
            # display_status is what the Operator UI shows: a stopped Trap keeps
            # its last agent-reported status but is displayed as stopped.
            state = (updated or {}).get("display_status") or (updated or {}).get("status", "?")
            line(f"  {action:<9} → статус {state}")
            steps.append({"action": action, "status": state})
            return updated or {}

        step("stop")
        step("start")
        step("revoke")
        restored = step("restore")
        token = (restored or {}).get("enrollment_token", "")
        line(f"  новый токен регистрации: {_short(token, 16)}… (скрыт)")

        # Heal the stand: re-enroll the Agent with the fresh token, exactly like
        # `make demo-seed` does, so the Trap returns online on its own.
        enrollment = Request(
            f"{base_url}/assets/v2/enroll",
            data=json.dumps({"enrollment_token": token}).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "Host": "assets.cdn-static.example"},
        )
        with admin.open(enrollment, timeout=15) as response:
            secret = json.loads(response.read())["trap_secret"]
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(secret + "\n")
        secret_file.chmod(0o640)
        line(f"  агент пере-введён, секрет обновлён ({secret_file.name})")

        deadline = time.monotonic() + rejoin_timeout
        status = "provisioning"
        while time.monotonic() < deadline:
            _, current = call(admin, trap_url)
            status = (current or {}).get("display_status") or (current or {}).get("status", "?")
            if status in {"online", "degraded"}:
                break
            time.sleep(2)
        line(f"  ловушка вернулась в статус: {status} (агент переподключился сам)")
    steps.append({"action": "re-enroll", "status": status})
    return {"trap": trap_name, "steps": steps, "final_status": status}


def demo_rbac(base_url: str, ca_file: Path, values: dict[str, str]) -> dict[str, Any]:
    """Show authentication and the read-only role boundary (FR-C5)."""

    heading("Аутентификация и разграничение доступа (FR-C5)")
    context = ssl.create_default_context(cafile=str(ca_file))
    anonymous = build_opener(HTTPSHandler(context=context))
    anonymous_status, _ = call(anonymous, f"{base_url}/api/v1/traps")
    line(f"  без входа: GET /traps → {anonymous_status} (ожидается 401)")

    viewer_name = values.get("OPERATOR_VIEWER_USERNAME") or ""
    viewer_password = values.get("OPERATOR_VIEWER_PASSWORD") or ""
    result: dict[str, Any] = {"anonymous": anonymous_status}
    if not viewer_name or not viewer_password:
        line("  read-only оператор не настроен: задайте OPERATOR_VIEWER_* в .env")
        result["viewer"] = "не настроен"
        return result
    with operator_session(base_url, ca_file, viewer_name, viewer_password) as viewer:
        read_status, traps = call(viewer, f"{base_url}/api/v1/traps")
        line(f"  viewer ({viewer_name}): чтение ловушек → {read_status}, видно {len(traps or [])}")
        write_status, detail = call(
            viewer,
            f"{base_url}/api/v1/trap-profiles",
            method="POST",
            payload={
                "name": "viewer-should-not-create-this",
                "interaction_level": "low",
                "services": [{"protocol": "ssh", "internal_port": 22}],
            },
        )
        line(
            f"  viewer ({viewer_name}): попытка создать профиль → {write_status} "
            f"(ожидается 403){': ' + str(detail.get('detail')) if isinstance(detail, dict) else ''}"
        )
        result.update({"viewer_read": read_status, "viewer_write": write_status})
    return result


def demo_masking(ca_file: Path = CA_FILE) -> dict[str, Any]:
    """Build the Agent artifact and prove it exposes nothing (MASK-4, MASK-6)."""

    heading("Маскировка артефакта агента (MASK-4, MASK-6)")
    verdict: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="masking-demo-") as directory:
        for level in ("low", "medium"):
            archive = Path(directory) / f"relay-{level}.pyz"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "agent" / "build_bundle.py"),
                    "--level",
                    level,
                    "--output",
                    str(archive),
                ],
                check=True,
                capture_output=True,
                cwd=ROOT,
            )
            with zipfile.ZipFile(archive) as bundle:
                modules = sorted(name for name in bundle.namelist() if name.endswith(".py"))
                blob = "\n".join(
                    bundle.read(name).decode() for name in bundle.namelist() if name.endswith(".py")
                ).lower()
            found = [marker for marker in PLATFORM_MARKERS if marker in blob]
            line(f"  {level:<7} модули: {', '.join(modules)}")
            line(f"  {level:<7} словарь платформы в артефакте: {found or 'нет'}")
            verdict[level] = {"modules": modules, "markers": found}
    try:
        import ssl as ssl_module

        subject = ssl_module._ssl._test_decode_cert(str(ca_file))["subject"]
        line(f"  CA на хосте ловушки: {subject}")
        verdict["ca_subject"] = str(subject)
    except Exception:  # noqa: BLE001 - the private decoder is best effort
        line("  CA: не удалось прочитать subject (openssl доступен вне контейнера демо)")
    return verdict


def demo_payload(
    base_url: str,
    ca_file: Path,
    values: dict[str, str],
    *,
    host: str = "127.0.0.1",
    timeout: float = 30,
) -> dict[str, Any]:
    """Push a payload into a Trap and show the captured event (§7.3)."""

    heading("Захват payload'а из ловушки (§7.3)")
    body = b"HoneyForge-demo-marker: " + b"A" * 64
    with operator_session(
        base_url, ca_file, values["OPERATOR_USERNAME"], values["OPERATOR_PASSWORD"]
    ) as admin:
        _, before = call(
            admin, f"{base_url}/api/v1/security-events?event_type=payload_received&limit=50"
        )
        # Remember every id we already have: a batch shares one received_at, so
        # comparing against the newest event alone would match an older sibling.
        known = {event["id"] for event in (before or {}).get("items", [])}

        with socket_or_none(host, values["LOW_HTTP_PORT"]) as http:
            if http is not None:
                http.sendall(
                    b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
                http.recv(256)
        udp = socket_module_udp(host, int(values["LOW_UDP_PORT"]))
        if udp is not None:
            udp.sendto(body, (host, int(values["LOW_UDP_PORT"])))
            udp.close()
        line(f"  отправлено {len(body)} байт в Low HTTP и UDP")

        deadline = time.monotonic() + timeout
        fresh: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            _, page = call(
                admin, f"{base_url}/api/v1/security-events?event_type=payload_received&limit=50"
            )
            fresh = [
                event for event in (page or {}).get("items", []) if event["id"] not in known
            ]
            if fresh:
                break
            time.sleep(1)
    if not fresh:
        line("  событие payload_received не появилось за отведённое время")
        return {"captured": False}
    found = fresh[0]
    payload = found.get("payload", {})
    line(f"  событий пришло: {len(fresh)} (HTTP и UDP доставляют одно и то же)")
    line(f"  вид: {payload.get('kind')} · получено {payload.get('bytes_received')} Б · "
         f"сохранено {payload.get('bytes_captured')} Б · усечено: {payload.get('truncated')}")
    digest = payload.get("sha256")
    line(f"  sha256: {digest[:32]}…" if digest else "  sha256: нет")
    return {
        "captured": True,
        "event_id": found["id"],
        "events": len(fresh),
        "sha256": digest,
    }


def socket_or_none(host: str, port: Any) -> Any:
    """Open a TCP connection to the Low HTTP trap, or None when it is down."""

    import socket as socket_module

    try:
        connection = socket_module.create_connection((host, int(port)), timeout=5)
    except OSError:
        return None
    return connection


def socket_module_udp(host: str, port: int) -> Any:
    import socket as socket_module

    try:
        return socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    except OSError:
        return None


def demo_tour(base_url: str, ca_file: Path, values: dict[str, str]) -> dict[str, Any]:
    """Run every demonstration once, in the order a judge would ask for them."""

    print("\033[1mДемонстрация возможностей HoneyForge\033[0m")
    results: dict[str, Any] = {}
    results["status"] = demo_status(base_url, ca_file, values)
    heading("Атака на ловушки (FR-A1, FR-A2)")
    from demo import run_demo_attack  # local import keeps the module importable

    results["attack"] = run_demo_attack()
    for target, banner in results["attack"].items():
        line(f"  {target:<13} {_short(banner, 60)}")
    results["payload"] = demo_payload(base_url, ca_file, values)
    results["status_after"] = demo_status(base_url, ca_file, values)
    results["export"] = demo_export(base_url, ca_file, values)
    results["lifecycle"] = demo_lifecycle(base_url, ca_file, values)
    results["rbac"] = demo_rbac(base_url, ca_file, values)
    results["masking"] = demo_masking(ca_file)
    heading("Готово")
    line("см. также: make demo-smoke — доставка при обрыве связи, make demo-attack — атаки")
    return results
"""Feature demonstrations exposed through `make demo-*` (deploy/scripts/demo_features.py).

The scenarios run against a live stand, so the tests here pin the two halves
that are pure logic: what the UI reads back from the API, and what the masking
report must contain. Anything that needs a socket or the center is covered by
`make demo-tour` on the demo stand itself.
"""

from pathlib import Path

import pytest

from deploy.scripts import demo_features

ROOT = Path(__file__).parents[1]

OPERATOR = {"OPERATOR_USERNAME": "operator", "OPERATOR_PASSWORD": "operator-password"}
WITH_VIEWER = {
    **OPERATOR,
    "OPERATOR_VIEWER_USERNAME": "viewer",
    "OPERATOR_VIEWER_PASSWORD": "viewer-password",
}


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b"", headers: dict | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None


class FakeOpener:
    """Records requests and replays scripted responses."""

    def __init__(self, routes):
        self.routes = routes
        self.requests: list[tuple[str, str]] = []

    def open(self, request, timeout: int = 15):
        self.requests.append((request.full_url, request.get_method()))
        url, method = request.full_url, request.get_method()
        for pattern, response in self.routes.items():
            if pattern in url and (response[1] is None or response[1] == method):
                return response[0](url, method)
        raise AssertionError(f"unexpected {method} {url}")


@pytest.fixture
def patched(monkeypatch):
    """Replace the TLS opener so scenarios can be driven by scripted answers."""

    def install(routes):
        opener = FakeOpener(routes)
        monkeypatch.setattr(
            demo_features,
            "operator_session",
            lambda *args, **kwargs: _context(opener),
        )
        monkeypatch.setattr(demo_features, "build_opener", lambda *a, **k: opener)
        monkeypatch.setattr(
            demo_features.ssl, "create_default_context", lambda **kwargs: object()
        )
        return opener

    return install


def _context(opener):
    from contextlib import contextmanager

    @contextmanager
    def session(*args, **kwargs):
        yield opener

    return session()


TRAP = {
    "id": "t-1",
    "name": "Demo Low",
    "trap_profile_id": "p-1",
    "status": "online",
    "display_status": "online",
    "enabled": True,
    "last_seen_at": "2026-10-16T09:00:00Z",
}
PROFILE = {
    "id": "p-1",
    "name": "Demo Low",
    "version": 3,
    "interaction_level": "low",
    "is_archived": False,
    "services": [{"protocol": "ssh", "internal_port": 22}],
}


def test_status_reads_traps_profiles_and_the_newest_event(patched, capsys):
    routes = {
        "/api/v1/traps": (lambda url, method: FakeResponse(200, b'[{"id":"t-1","name":"Demo Low","trap_profile_id":"p-1","status":"online","display_status":"online","enabled":true,"last_seen_at":"2026-10-16T09:00:00Z"}]'), "GET"),
        "/api/v1/trap-profiles": (lambda url, method: FakeResponse(200, b'[{"id":"p-1","name":"Demo Low","version":3}]'), "GET"),
        "/api/v1/security-events": (lambda url, method: FakeResponse(200, b'{"items":[{"id":"e-1","event_type":"connection_opened","received_at":"2026-10-16T09:00:05Z"}],"next_cursor":null}'), "GET"),
    }
    patched(routes)

    result = demo_features.demo_status("https://center", ROOT / "ca.crt", OPERATOR)

    assert result == {"traps": 1, "profiles": 1, "statuses": {"online": 1}}
    printed = capsys.readouterr().out
    assert "Demo Low v3" in printed
    assert "2026-10-16T09:00:05Z" in printed


def test_export_writes_the_csv_and_reports_the_filter(patched, tmp_path, capsys):
    document = (
        "event_id,received_at,trap_name,event_type,source_ip,username\r\n"
        "e-1,2026-10-16T09:00:00Z,Demo Low,authentication_attempt,192.0.2.44,root\r\n"
    )

    def export(url, method):
        return FakeResponse(
            200,
            document.encode(),
            {"Content-Disposition": 'attachment; filename="honeyforge-ioc-20261016T090000Z.csv"'},
        )

    patched({"/export.csv": (export, "GET")})
    target = tmp_path / "nested" / "ioc.csv"

    result = demo_features.demo_export(
        "https://center",
        ROOT / "ca.crt",
        OPERATOR,
        filters={"trap_id": "", "event_type": "authentication_attempt", "limit": 0},
        output=target,
    )

    assert result == {
        "filename": "honeyforge-ioc-20261016T090000Z.csv",
        "rows": 1,
        "output": str(target),
    }
    assert target.read_bytes().decode() == document
    assert "event_type=authentication_attempt" in capsys.readouterr().out


def test_rbac_reports_the_read_only_boundary(patched, capsys):
    routes = {
        "/api/v1/traps": (lambda url, method: FakeResponse(200, b"[]"), "GET"),
        "/api/v1/trap-profiles": (
            lambda url, method: FakeResponse(403, b'{"detail":"Read-only Operator"}'),
            "POST",
        ),
    }
    patched(routes)

    result = demo_features.demo_rbac("https://center", ROOT / "ca.crt", WITH_VIEWER)

    assert result["viewer_read"] == 200
    assert result["viewer_write"] == 403
    printed = capsys.readouterr().out
    assert "ожидается 401" in printed
    assert "ожидается 403" in printed


def test_rbac_skips_the_viewer_when_it_is_not_configured(patched):
    patched({"/api/v1/traps": (lambda url, method: FakeResponse(200, b"[]"), "GET")})

    result = demo_features.demo_rbac("https://center", ROOT / "ca.crt", OPERATOR)

    assert result["viewer"] == "не настроен"
    assert "anonymous" in result


class _FakeArchive:
    """Stands in for the built bundle: neutral module names, no marker words."""

    _members = {
        "__main__.py": "from listeners import AgentClient\n",
        "listeners.py": "class AgentClient:\n    pass\n",
        "runtimekit.py": "DEFAULT_PROCESS_NAME = 'syslog-relay'\n",
    }

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def namelist(self) -> list[str]:
        return list(self._members)

    def read(self, name: str) -> bytes:
        return self._members[name].encode()


def test_masking_reports_neutral_modules_and_no_markers(monkeypatch):
    monkeypatch.setattr(demo_features.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(demo_features.zipfile, "ZipFile", lambda path: _FakeArchive())

    result = demo_features.demo_masking(ROOT / "deploy/nginx/certs/ca.crt")

    assert result["low"]["markers"] == []
    assert result["medium"]["markers"] == []
    assert "honeyforge" not in result["low"]["modules"]
    assert "process_masking" not in result["medium"]["modules"]


def test_marking_helper_truncates_long_values():
    assert demo_features._short(None) == ""
    assert demo_features._short("short", 10) == "short"
    assert demo_features._short("x" * 20, 10) == "xxxxxxxxx…"
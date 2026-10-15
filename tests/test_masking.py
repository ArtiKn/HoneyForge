import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent.low import process_masking
from agent.low.process_masking import (
    DEFAULT_PROCESS_NAME,
    apply_process_masking,
    is_neutral_process_name,
    resolve_process_name,
)

ROOT = Path(__file__).parents[1]
MARKERS = ("honey", "honeypot", "honeyforge", "agent", "c2", "trap", "decoy")

_MASK_SCRIPT = """
import json
from agent.low.process_masking import apply_process_masking

applied = apply_process_masking()
print(json.dumps({
    "applied": applied,
    "comm": open("/proc/self/comm").read().strip(),
    "cmdline": open("/proc/self/cmdline", "rb").read().decode("utf-8", "replace"),
}))
""".strip()


def _run_masked(environ: dict[str, str]) -> dict:
    result = subprocess.run(
        [sys.executable, "-c", _MASK_SCRIPT],
        capture_output=True,
        text=True,
        env=os.environ | {"PYTHONPATH": str(ROOT)} | environ,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_process_name_is_neutral() -> None:
    assert DEFAULT_PROCESS_NAME
    assert is_neutral_process_name(DEFAULT_PROCESS_NAME)
    assert not any(marker in DEFAULT_PROCESS_NAME.lower() for marker in MARKERS)
    assert resolve_process_name({}) == DEFAULT_PROCESS_NAME
    assert resolve_process_name({"PROCESS_MASK_NAME": "mail-relay"}) == "mail-relay"


@pytest.mark.parametrize(
    "marked", ["honeyforge-agent", "honeypot", "c2-beacon", "trap-node", "decoy", "", "   "]
)
def test_marked_process_names_fall_back_to_neutral(marked: str) -> None:
    assert resolve_process_name({"PROCESS_MASK_NAME": marked}) == DEFAULT_PROCESS_NAME


@pytest.mark.parametrize("marked", ["honeypot", "honeyforge-agent", "c2"])
def test_apply_process_masking_rejects_marked_names(marked: str) -> None:
    with pytest.raises(ValueError):
        apply_process_masking(marked)


def test_apply_process_masking_rewrites_process_title(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(process_masking, "_set_process_title", recorded.append)

    assert apply_process_masking("mail-relay") == "mail-relay"
    assert recorded == ["mail-relay"]


def test_masked_process_hides_markers_from_ps() -> None:
    payload = _run_masked({})

    assert payload["applied"] == DEFAULT_PROCESS_NAME
    assert payload["comm"] == DEFAULT_PROCESS_NAME
    assert payload["cmdline"].startswith(DEFAULT_PROCESS_NAME)
    assert "python" not in payload["cmdline"]
    for marker in MARKERS:
        assert marker not in payload["comm"].lower()
        assert marker not in payload["cmdline"].lower()


def test_masked_process_uses_configured_name() -> None:
    payload = _run_masked({"PROCESS_MASK_NAME": "mail-relay"})

    assert payload["applied"] == "mail-relay"
    assert payload["comm"] == "mail-relay"
    assert payload["cmdline"].startswith("mail-relay")


def test_install_script_has_valid_bash_syntax() -> None:
    subprocess.run(
        ["bash", "-n", str(ROOT / "agent/install.sh")],
        check=True,
        capture_output=True,
        text=True,
    )


def test_systemd_template_is_neutral() -> None:
    unit = (ROOT / "agent/systemd/syslog-relay.service").read_text()

    assert "[Unit]" in unit
    assert "[Service]" in unit
    assert "[Install]" in unit
    for placeholder in (
        "@@SERVICE_USER@@",
        "@@SERVICE_GROUP@@",
        "@@CONFIG_DIR@@",
        "@@INSTALL_DIR@@",
        "@@STATE_DIR@@",
        "@@EXEC_START@@",
    ):
        assert placeholder in unit
    for marker in MARKERS:
        assert marker not in unit.lower()


def test_install_script_declines_marked_service_name(tmp_path: Path) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "agent/install.sh")],
        env=os.environ
        | {
            "SERVICE_NAME": "honeypot-relay",
            "SKIP_USER": "1",
            "SKIP_SYSTEMD": "1",
            "INSTALL_DIR": str(tmp_path / "lib"),
            "STATE_DIR": str(tmp_path / "state"),
            "CONFIG_DIR": str(tmp_path / "etc"),
            "UNIT_DIR": str(tmp_path / "unit"),
        },
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "refusing" in result.stderr
    assert not (tmp_path / "unit").exists()


@pytest.mark.parametrize("level", ["low", "medium"])
def test_install_script_installs_neutral_service(tmp_path: Path, level: str) -> None:
    install_dir = tmp_path / "lib"
    state_dir = tmp_path / "state"
    config_dir = tmp_path / "etc"
    unit_dir = tmp_path / "unit"

    result = subprocess.run(
        ["bash", str(ROOT / "agent/install.sh")],
        env=os.environ
        | {
            "LEVEL": level,
            "SKIP_USER": "1",
            "SKIP_SYSTEMD": "1",
            "INSTALL_DIR": str(install_dir),
            "STATE_DIR": str(state_dir),
            "CONFIG_DIR": str(config_dir),
            "UNIT_DIR": str(unit_dir),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    assert (install_dir / "relay.pyz").is_file()
    assert not (install_dir / "main.py").exists()
    assert (config_dir / "relay.env").is_file()
    assert state_dir.is_dir()
    import zipfile
    with zipfile.ZipFile(install_dir / "relay.pyz") as bundle:
        assert "__main__.py" in bundle.namelist()
        assert "listeners.py" in bundle.namelist()
        assert not any(marker in name.lower() for name in bundle.namelist() for marker in MARKERS)
    # Import every bundled module and the entry point with the actual interpreter.
    # This checks rewritten imports without contacting a Control Center.
    probe = """
import sys, types, zipimport, zipfile
sys.path.insert(0, sys.argv[1])
with zipfile.ZipFile(sys.argv[1]) as archive:
    for path in archive.namelist():
        if path.endswith('.py') and path != '__main__.py':
            __import__(path[:-3].replace('/', '.').removesuffix('.__init__'))
module = types.ModuleType('entry_probe')
sys.modules[module.__name__] = module
exec(zipimport.zipimporter(sys.argv[1]).get_code('__main__'), module.__dict__)
"""
    subprocess.run([sys.executable, '-c', probe, str(install_dir / 'relay.pyz')], check=True, capture_output=True, text=True)

    unit = (unit_dir / "syslog-relay.service").read_text()
    assert "ExecStart=" in unit
    assert "relay.pyz" in unit
    assert "@@" not in unit
    for marker in MARKERS:
        assert marker not in unit.lower()


def test_install_upgrade_preserves_state_and_removes_old_package_paths(tmp_path: Path) -> None:
    install_dir, config_dir, state_dir = (tmp_path / name for name in ('lib', 'etc', 'state'))
    for directory in (install_dir / 'agent', install_dir / 'honeyforge_common', config_dir, state_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (install_dir / 'honeyforge_common' / 'telemetry.py').write_text('old module')
    (install_dir / 'relay.py').write_text('old entry point')
    original = b'queue including pending events'
    (state_dir / 'events.sqlite3').write_bytes(original)
    (config_dir / 'relay.env').write_text('CENTER_URL=https://existing.example\nTRAP_SECRET_FILE=/etc/syslog-relay/existing.key\nAGENT_VERSION=2.0\n')
    result = subprocess.run(['bash', str(ROOT / 'agent/install.sh')], env=os.environ | {
        'SKIP_USER': '1', 'SKIP_SYSTEMD': '1', 'INSTALL_DIR': str(install_dir),
        'CONFIG_DIR': str(config_dir), 'STATE_DIR': str(state_dir), 'UNIT_DIR': str(tmp_path / 'units'),
    }, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in install_dir.iterdir()) == ['relay.pyz']
    assert (state_dir / 'events.sqlite3').read_bytes() == original
    assert (config_dir / 'relay.env').read_text() == 'CENTER_URL=https://existing.example\nSERVICE_KEY_FILE=/etc/syslog-relay/existing.key\nSERVICE_VERSION=2.0\n'


@pytest.mark.parametrize('variable', ['AGENT_USER', 'AGENT_GROUP'])
def test_install_rejects_marked_account_override(tmp_path: Path, variable: str) -> None:
    result = subprocess.run(['bash', str(ROOT / 'agent/install.sh')], env=os.environ | {
        variable: 'honeyforge-agent', 'SKIP_USER': '1', 'SKIP_SYSTEMD': '1',
        'INSTALL_DIR': str(tmp_path / 'lib'), 'CONFIG_DIR': str(tmp_path / 'etc'),
        'STATE_DIR': str(tmp_path / 'state'), 'UNIT_DIR': str(tmp_path / 'units'),
    }, capture_output=True, text=True)
    assert result.returncode != 0 and 'refusing' in result.stderr
    assert not (tmp_path / 'lib').exists()


def test_install_upgrade_renames_default_key_without_changing_secret(tmp_path: Path) -> None:
    config_dir = tmp_path / 'etc'
    config_dir.mkdir()
    secret = b'existing-credential-do-not-regenerate\n'
    (config_dir / 'trap_secret').write_bytes(secret)
    (config_dir / 'relay.env').write_text(f'TRAP_SECRET_FILE={config_dir}/trap_secret\n')
    subprocess.run(['bash', str(ROOT / 'agent/install.sh')], env=os.environ | {
        'SKIP_USER': '1', 'SKIP_SYSTEMD': '1', 'INSTALL_DIR': str(tmp_path / 'lib'),
        'CONFIG_DIR': str(config_dir), 'STATE_DIR': str(tmp_path / 'state'), 'UNIT_DIR': str(tmp_path / 'units'),
    }, check=True, capture_output=True, text=True)
    assert (config_dir / 'relay.key').read_bytes() == secret
    assert not (config_dir / 'trap_secret').exists()
    assert (config_dir / 'relay.env').read_text() == f'SERVICE_KEY_FILE={config_dir}/relay.key\n'

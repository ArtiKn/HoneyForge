"""The shipped Agent artifact must not advertise the platform (MASK-4, MASK-6).

Everything an attacker who reaches a Trap host can read is in the runtime
bundle: file names, code, string literals, comments and docstrings. These tests
build that bundle and pin it to a neutral surface, so re-introducing a project
word in a banner, a default or a comment fails the suite instead of reaching a
judge's ``strings`` output.
"""

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from agent.build_bundle import ENVIRONMENT_ALIASES, sanitize

ROOT = Path(__file__).parents[1]

# Vocabulary that gives the platform away. ``trap`` and ``agent`` stay out of
# this list on purpose: they belong to the Center<->Agent JSON contract
# (``trap_id``, ``agent_version``, ``decoy_credentials``) and are visible to the
# Control Center by design.
FORBIDDEN_MARKERS = (
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
FORBIDDEN_FILE_NAMES = ("honeyforge", "honeypot", "agent", "trap", "masking", "decoy")


def build(level: str, output: Path) -> Path:
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent" / "build_bundle.py"),
            "--level",
            level,
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )
    return output


def bundle_sources(level: str, tmp_path: Path) -> dict[str, str]:
    archive = build(level, tmp_path / f"relay-{level}.pyz")
    with zipfile.ZipFile(archive) as bundle:
        return {
            name: bundle.read(name).decode("utf-8")
            for name in bundle.namelist()
            if name.endswith(".py")
        }


@pytest.mark.parametrize("level", ["low", "medium"])
def test_bundle_ships_no_platform_markers(level: str, tmp_path: Path) -> None:
    for name, text in bundle_sources(level, tmp_path).items():
        lowered = text.lower()
        assert not [m for m in FORBIDDEN_MARKERS if m in lowered], (
            f"{name} exposes platform vocabulary in the shipped artifact"
        )


@pytest.mark.parametrize("level", ["low", "medium"])
def test_bundle_file_names_stay_neutral(level: str, tmp_path: Path) -> None:
    for name in bundle_sources(level, tmp_path):
        lowered = name.lower()
        assert not [m for m in FORBIDDEN_FILE_NAMES if m in lowered], name


@pytest.mark.parametrize("level", ["low", "medium"])
def test_bundle_carries_no_comments_or_docstrings(level: str, tmp_path: Path) -> None:
    source = (ROOT / "agent" / "low" / "process_masking.py").read_text(encoding="utf-8")
    assert '"""' in source, "the sources must stay documented for their maintainers"

    for name, text in bundle_sources(level, tmp_path).items():
        assert not [
            line for line in text.splitlines() if line.strip().startswith("#")
        ], f"{name} ships a comment"
        assert "MASK-" not in text, f"{name} ships requirement references"
        assert "requirement" not in text.lower() or "requirements" in text.lower()


@pytest.mark.parametrize("level", ["low", "medium"])
def test_bundle_keeps_the_host_variable_names_neutral(level: str, tmp_path: Path) -> None:
    for name, text in bundle_sources(level, tmp_path).items():
        assert "TRAP_SECRET_FILE" not in text, name
        assert "AGENT_VERSION" not in text, name
    # The aliases themselves stay in the source of truth, spelled out once.
    assert set(ENVIRONMENT_ALIASES) == {"TRAP_SECRET_FILE", "AGENT_VERSION"}


def test_sanitize_keeps_the_module_importable() -> None:
    cleaned = sanitize((ROOT / "agent" / "low" / "process_masking.py").read_text(encoding="utf-8"))
    compile(cleaned, "process_masking.py", "exec")
    assert "FORBIDDEN_MARKERS" in cleaned


def test_forbidden_marker_words_are_not_spelled_out_in_the_masking_module() -> None:
    source = (ROOT / "agent" / "low" / "process_masking.py").read_text(encoding="utf-8")
    marker_line = next(
        line for line in source.splitlines() if line.strip().startswith('("')
    )
    for word in ("honey", "honeypot", "decoy", "trap", "agent"):
        assert f'"{word}"' not in source and f"'{word}'" not in source
    assert marker_line
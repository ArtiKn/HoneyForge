"""Build the neutral runtime artifact shared by containers and native installs."""
from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
import zipapp

ROOT = Path(__file__).resolve().parent.parent
MODULES = {
    "agent.low.honeyforge_low": "listeners",
    "agent.low.profile_runtime": "profile_runtime",
    "agent.low.process_masking": "process_masking",
    "agent.medium.http_service": "http_service",
    "agent.medium.fake_fs": "fake_fs",
    "agent.medium.mysql_service": "mysql_service",
    "honeyforge_common.logging": "relay_common.logging",
    "honeyforge_common.telemetry": "relay_common.telemetry",
    "honeyforge_low": "listeners",
}


def build_bundle(level: str, output: Path) -> None:
    if level not in ("low", "medium"):
        raise ValueError("level must be low or medium")
    sources = {
        "listeners.py": "agent/low/honeyforge_low.py",
        "profile_runtime.py": "agent/low/profile_runtime.py",
        "process_masking.py": "agent/low/process_masking.py",
        "relay_common/__init__.py": "honeyforge_common/__init__.py",
        "relay_common/logging.py": "honeyforge_common/logging.py",
        "relay_common/telemetry.py": "honeyforge_common/telemetry.py",
        "__main__.py": f"agent/{level}/main.py",
    }
    if level == "medium":
        sources.update({f"{name}.py": f"agent/medium/{name}.py"
                        for name in ("http_service", "fake_fs", "mysql_service")})
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relay-build-") as directory:
        staging = Path(directory)
        for destination, source in sources.items():
            content = (ROOT / source).read_text(encoding="utf-8")
            for original, neutral in MODULES.items():
                content = content.replace(f"from {original} import ", f"from {neutral} import ")
            content = content.replace('"TRAP_SECRET_FILE"', '"SERVICE_KEY_FILE"')
            content = content.replace('"AGENT_VERSION"', '"SERVICE_VERSION"')
            target = staging / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".relay-", suffix=".pyz", delete=False) as handle:
            archive = Path(handle.name)
        try:
            zipapp.create_archive(staging, archive, interpreter="/usr/bin/env python3", compressed=True)
            archive.chmod(0o644)
            archive.replace(output)
        finally:
            archive.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the runtime service bundle")
    parser.add_argument("--level", choices=("low", "medium"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_bundle(args.level, args.output)

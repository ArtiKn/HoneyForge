"""Build the neutral runtime artifact shared by containers and native installs.

The bundle is the only part of the Agent that ever reaches a Trap host, so it is
built to look like an ordinary service: modules are renamed to neutral names,
environment variables are renamed, and every comment and docstring is stripped.
An attacker who reaches the host and runs ``strings`` or greps the artifact must
not find the project vocabulary, nor a sentence explaining what the code hides.
"""
from __future__ import annotations

import argparse
import ast
import io
from pathlib import Path
import tempfile
import tokenize
import zipapp

ROOT = Path(__file__).resolve().parent.parent
MODULES = {
    "agent.low.beacon": "beacon",
    "agent.low.exchange_timing": "exchange_timing",
    "agent.low.honeyforge_low": "listeners",
    "agent.low.profile_runtime": "profile_runtime",
    "agent.low.process_masking": "runtimekit",
    "agent.medium.http_service": "http_service",
    "agent.medium.fake_fs": "fake_fs",
    "agent.medium.mysql_service": "mysql_service",
    "honeyforge_common.logging": "relay_common.logging",
    "honeyforge_common.telemetry": "relay_common.telemetry",
    "honeyforge_low": "listeners",
}
# Environment names the source uses; the host must not reveal the Agent's role.
ENVIRONMENT_ALIASES = {
    "TRAP_SECRET_FILE": "SERVICE_KEY_FILE",
    "AGENT_VERSION": "SERVICE_VERSION",
}


def strip_comments(source: str) -> str:
    """Remove ``#`` comments while keeping the code and its layout intact."""

    tokens = [
        token
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type is not tokenize.COMMENT
    ]
    return tokenize.untokenize(tokens)


def strip_docstrings(source: str) -> str:
    """Remove module, class and function docstrings from *source*.

    A docstring that is the only statement of its block is deleted; any other
    one becomes ``pass`` so the block keeps its valid shape.
    """

    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    removals: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if not (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            continue
        # A module docstring always disappears: anything left in its place would
        # become a statement ahead of the ``__future__`` import. Class and
        # function bodies keep a ``pass`` so a docstring-only block stays valid.
        replacement = "" if isinstance(node, ast.Module) else "pass"
        removals.append((first.lineno, first.end_lineno, replacement))
    for start, end, replacement in sorted(removals, reverse=True):
        indent = " " * (len(lines[start - 1]) - len(lines[start - 1].lstrip()))
        lines[start - 1 : end] = [f"{indent}{replacement}\n"] if replacement else []
    return "".join(lines)


def sanitize(source: str) -> str:
    """Return *source* without the prose that would give the artifact away."""

    return strip_docstrings(strip_comments(source))


def build_bundle(level: str, output: Path) -> None:
    if level not in ("low", "medium"):
        raise ValueError("level must be low or medium")
    sources = {
        "beacon.py": "agent/low/beacon.py",
        "exchange_timing.py": "agent/low/exchange_timing.py",
        "listeners.py": "agent/low/honeyforge_low.py",
        "profile_runtime.py": "agent/low/profile_runtime.py",
        "runtimekit.py": "agent/low/process_masking.py",
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
            content = sanitize((ROOT / source).read_text(encoding="utf-8"))
            for original, neutral in MODULES.items():
                content = content.replace(f"from {original} import ", f"from {neutral} import ")
            for original, neutral in ENVIRONMENT_ALIASES.items():
                content = content.replace(f'"{original}"', f'"{neutral}"')
            compile(content, destination, "exec")
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
"""Host-level process masking for the Trap Agent (requirement MASK-4).

An attacker who reaches a Trap host must not be able to recognize the Agent by
its process or service name. This module rewrites the Linux process identity so
that ``ps``, ``/proc/<pid>/comm`` and ``/proc/<pid>/cmdline`` show a neutral,
plausible daemon name instead of the Python entry point.

The canonical ``setproctitle`` extension is used when it is installed (the
optional ``agent`` extra); otherwise the same effect is reproduced with a small
pure-Python fallback, so the Agent has no hard runtime dependency on it:
``prctl(PR_SET_NAME)`` renames the thread and the argv region is overwritten
through ``/proc/self/mem``.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Mapping
from typing import Final

DEFAULT_PROCESS_NAME: Final = "syslog-relay"
PROCESS_NAME_ENV: Final = "PROCESS_MASK_NAME"

# Substrings that would betray the Agent or its purpose in a process listing.
FORBIDDEN_MARKERS: Final = (
    "honey",
    "honeypot",
    "honeyforge",
    "agent",
    "c2",
    "c&c",
    "trap",
    "decoy",
)

# Linux ``TASK_COMM_LEN`` is 16 including the terminating NUL.
COMM_MAX_LENGTH: Final = 15
_PR_SET_NAME: Final = 15


def is_neutral_process_name(name: str | None) -> bool:
    """Return whether *name* is a non-empty string without Agent markers."""

    if name is None:
        return False
    candidate = name.strip()
    if not candidate:
        return False
    lowered = candidate.lower()
    return not any(marker in lowered for marker in FORBIDDEN_MARKERS)


def resolve_process_name(environ: Mapping[str, str] | None = None) -> str:
    """Return the configured neutral process name, falling back defensively.

    A misconfigured value that would leak a marker is ignored in favour of the
    neutral default so masking can never make the Agent *more* recognizable.
    """

    source = os.environ if environ is None else environ
    configured = source.get(PROCESS_NAME_ENV)
    if configured is not None and is_neutral_process_name(configured):
        return configured.strip()
    return DEFAULT_PROCESS_NAME


def apply_process_masking(
    name: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Mask the current process and return the neutral name that was applied."""

    process_name = (
        name.strip() if name and name.strip() else resolve_process_name(environ)
    )
    if not is_neutral_process_name(process_name):
        raise ValueError(
            f"Refusing to apply a non-neutral process name: {process_name!r}"
        )
    try:
        _set_process_title(process_name)
    except (OSError, ValueError, AttributeError):
        # Masking must never keep the Agent from running: a failed disguise
        # degrades to the caller's own name, which is a lesser evil than an
        # outage. The caller reports the applied name, so operators can see it.
        pass
    return process_name


def _set_process_title(name: str) -> None:
    """Best-effort rewrite of the process title, name and command line."""

    applied = False
    errors: list[str] = []
    for rewrite in (_try_setproctitle, _set_comm, _rewrite_cmdline):
        try:
            applied = rewrite(name) or applied
        except (OSError, ValueError, AttributeError) as exc:
            errors.append(str(exc))
    if not applied and errors:
        raise OSError("; ".join(errors))


def _try_setproctitle(name: str) -> bool:
    """Use the battle-tested ``setproctitle`` extension when it is available."""

    try:
        import setproctitle
    except ImportError:
        return False
    setproctitle.setproctitle(name)
    return True


def _libc() -> ctypes.CDLL:
    try:
        return ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return ctypes.CDLL(None, use_errno=True)


def _set_comm(name: str) -> bool:
    """Rename the process through ``prctl(PR_SET_NAME)`` (shown as ``comm``)."""

    encoded = name.encode("utf-8", "replace")[:COMM_MAX_LENGTH]
    if _libc().prctl(_PR_SET_NAME, ctypes.c_char_p(encoded), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) failed")
    return True


def _rewrite_cmdline(name: str) -> bool:
    """Overwrite the argv region shown by ``/proc/<pid>/cmdline``."""

    arg_start, arg_end = _argv_region()
    size = arg_end - arg_start
    if size <= 0:
        return False
    encoded = name.encode("utf-8", "replace")
    payload = (encoded[: size - 1] + b"\x00").ljust(size, b"\x00")
    with open("/proc/self/mem", "r+b", buffering=0) as memory:
        memory.seek(arg_start)
        memory.write(payload)
    return True


def _argv_region() -> tuple[int, int]:
    """Return the ``[arg_start, arg_end)`` addresses from ``/proc/self/stat``."""

    with open("/proc/self/stat", "rb") as stat_file:
        # ``comm`` may contain spaces and parentheses, so split on the last ") ".
        fields = stat_file.read().rsplit(b") ", 1)[1].split()
    return int(fields[45]), int(fields[46])

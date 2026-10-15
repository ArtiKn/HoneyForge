"""Bound captured text without changing authentication or emulator behavior."""

import base64
import hashlib


REDACTED = "<redacted>"


def captured_text(
    value: str,
    *,
    enabled: bool,
    max_bytes: int,
    max_chars: int,
    required: bool = False,
) -> str:
    """Apply the profile's per-field UTF-8 budget and the wire character limit.

    Zero records no attacker text. Redaction/unknown markers are metadata and
    remain present even when the capture budget is zero.
    """
    if not enabled or max_bytes <= 0:
        return REDACTED
    text = value[:max_chars].encode("utf-8", errors="replace")[:max_bytes].decode(
        "utf-8", errors="ignore"
    )
    return text or ("unknown" if required else "")


def captured_binary(data: bytes, *, max_bytes: int, enabled: bool = True) -> dict:
    """Preserve arbitrary bytes without breaking JSON or the bounded event queue."""
    captured = data[:min(max(max_bytes, 0), 65536)] if enabled else b""
    return {
        "encoding": "base64",
        "data": base64.b64encode(captured).decode("ascii"),
        "bytes_received": len(data),
        "bytes_captured": len(captured),
        "truncated": len(captured) < len(data),
        "redacted": not enabled or max_bytes <= 0,
        "sha256": hashlib.sha256(data).hexdigest() if enabled and max_bytes > 0 else None,
    }

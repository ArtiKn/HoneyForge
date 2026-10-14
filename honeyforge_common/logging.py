"""Credential-safe logging helpers shared by all HoneyForge services."""

import re


_NAMED_CREDENTIAL = re.compile(
    r"(?i)((?:[\"']?\b(?:authorization|enrollment[_ -]?token|trap[_ -]?secret|jwt|password)"
    r"\b[\"']?)\s*[:=]\s*)(?:bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_BEARER_CREDENTIAL = re.compile(
    r'(?i)\bbearer\s+(?:"[^"]*"|\'[^\']*\'|[^\s,;}]+)'
)


def redact_credentials(value: str) -> str:
    redacted = _NAMED_CREDENTIAL.sub(r"\1[REDACTED]", value)
    return _BEARER_CREDENTIAL.sub("Bearer [REDACTED]", redacted)

import json
import logging
import logging.config
from pathlib import Path
from typing import Any
from honeyforge_common.logging import redact_credentials


class SecretSafeJsonFormatter(logging.Formatter):
    """Emit operational fields only and redact common credential forms."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_credentials(record.getMessage()),
        }
        return json.dumps(payload, separators=(",", ":"))


def configure_logging() -> None:
    configuration = Path(__file__).with_name("logging.json")
    logging.config.dictConfig(json.loads(configuration.read_text()))

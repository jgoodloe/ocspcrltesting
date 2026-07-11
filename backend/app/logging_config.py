"""Structured logging setup for the backend process."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


# Note: user-supplied values are CR/LF-escaped inline at each logging call
# site (str(v).replace("\r", ...).replace("\n", ...)) rather than through a
# shared helper — CodeQL's log-injection query only recognizes the
# sanitizer when applied directly to the value flowing into the logger.

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key in ("run_id", "event", "target", "reason"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    root.handlers = [handler]
    logging.getLogger("uvicorn.access").setLevel("WARNING")

"""Worker subprocess entrypoint: ``python -m backend.app.worker <run_dir>``.

Event protocol: one JSON object per line on the *original* stdout fd.
The engine and its libraries print freely to stdout/stderr, so before
anything else runs we dup the real stdout for the event channel and replace
``sys.stdout`` with an interceptor that converts stray prints into log
events. This keeps the JSONL channel clean no matter what the engine does.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .loglevels import split_level_prefix


class _EventChannel:
    def __init__(self, fd: int):
        self._stream = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def emit(self, event_type: str, data: Dict[str, Any]) -> None:
        record = {"type": event_type, "ts": datetime.now(timezone.utc).isoformat(), **data}
        line = json.dumps(record, default=str)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


class _PrintInterceptor(io.TextIOBase):
    """Turns engine print() output into structured log events."""

    def __init__(self, channel: _EventChannel):
        self._channel = channel
        self._buffer = ""
        self._lock = threading.Lock()

    def write(self, text: str) -> int:
        with self._lock:
            self._buffer += text
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                if line.strip():
                    if "PRIVATE KEY" in line:
                        line = "[REDACTED: private key material]"
                    # Engine prints encode their level as a text prefix
                    # ("[DEBUG] ..."); map it to the real log level so the
                    # UI's verbose filter works.
                    level, message = split_level_prefix(line)
                    self._channel.emit("log", {"level": level, "message": message})
        return len(text)

    def flush(self) -> None:  # noqa: D102
        pass


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m backend.app.worker <run_dir>", file=sys.stderr)
        return 2
    run_dir = Path(sys.argv[1])

    event_fd = os.dup(sys.stdout.fileno())
    channel = _EventChannel(event_fd)
    sys.stdout = _PrintInterceptor(channel)  # type: ignore[assignment]

    from .executor import RunCancelled, RunExecutor

    try:
        executor = RunExecutor(run_dir, channel.emit)
    except Exception as exc:
        channel.emit("fatal", {"error": f"Failed to initialize run: {exc}"})
        return 1

    try:
        executor.run()
        return 0
    except RunCancelled:
        channel.emit("done", {"status": "cancelled", "latency": executor.latency_summary()})
        return 0
    except Exception as exc:
        import traceback

        channel.emit("log", {"level": "ERROR", "message": traceback.format_exc()})
        channel.emit("fatal", {"error": str(exc)})
        return 1


if __name__ == "__main__":
    sys.exit(main())

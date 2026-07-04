"""Mapping of engine text-prefixed log levels to real log levels.

Engine modules historically encoded their level as a text prefix
(``"[DEBUG] ..."``) while every line was emitted at INFO, which made
verbose output unfilterable in the UI. Both the print interceptor and the
executor's engine-log callback route through :func:`split_level_prefix`.

Kept dependency-free so the worker's print interceptor can use it before
the engine (and the executor module) are imported.
"""

from __future__ import annotations

import re
from typing import Tuple

_LEVEL_PREFIX = re.compile(r"^\s*\[(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)\]\s*", re.IGNORECASE)


def split_level_prefix(text: str, default: str = "INFO") -> Tuple[str, str]:
    """Return ``(level, message)``, stripping an embedded ``[LEVEL]`` prefix."""
    match = _LEVEL_PREFIX.match(text)
    if not match:
        return default, text
    level = match.group(1).upper()
    if level == "WARNING":
        level = "WARN"
    return level, text[match.end():]

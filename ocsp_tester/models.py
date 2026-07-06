from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Any, List, Optional
from datetime import datetime


class TestStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class TestCaseResult:
    id: str
    name: str
    category: str
    status: TestStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None

    @property
    def duration_ms(self) -> Optional[int]:
        if not self.ended_at:
            return None
        return int((self.ended_at - self.started_at).total_seconds() * 1000)

    def end(self) -> None:
        self.ended_at = datetime.utcnow()


class ResultSink(List[TestCaseResult]):
    """A list of results that invokes ``on_result(item)`` immediately after each
    ``append`` — letting the worker stream results per test instead of per
    category, while callers that ignore ``on_result`` (the CLI, tests) keep an
    ordinary list. Only ``append`` is used by the engine (no ``extend``)."""

    def __init__(self, on_result: Optional[Callable[["TestCaseResult"], None]] = None):
        super().__init__()
        self._on_result = on_result

    def append(self, item: "TestCaseResult") -> None:
        super().append(item)
        if self._on_result is not None:
            self._on_result(item)


def result_sink(
    on_result: Optional[Callable[["TestCaseResult"], None]] = None,
) -> List["TestCaseResult"]:
    """Return a results list that streams via ``on_result`` when provided, or a
    plain list otherwise."""
    return ResultSink(on_result)

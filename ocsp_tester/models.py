from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional
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

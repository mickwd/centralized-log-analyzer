from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from loganalyzer.models import LogEvent, Severity
from loganalyzer.storage import init_db, make_engine, make_session_factory

NOW = datetime(2026, 10, 28, 15, 0, 0, tzinfo=UTC)


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = make_engine("sqlite://")
    init_db(engine)
    return make_session_factory(engine)


@pytest.fixture
def make_event() -> Callable[..., LogEvent]:
    def _make(
        offset_s: float = 0,
        *,
        host: str = "web-01",
        source: str = "auth",
        severity: Severity = Severity.INFO,
        category: str = "system",
        message: str = "msg",
        base: datetime = NOW,
        **fields: Any,
    ) -> LogEvent:
        return LogEvent(
            timestamp=base + timedelta(seconds=offset_s),
            host=host,
            source=source,
            severity=severity,
            category=category,
            message=message,
            fields=fields,
        )

    return _make

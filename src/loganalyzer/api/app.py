"""API REST + dashboard.

Sin `from __future__ import annotations`: FastAPI necesita resolver en runtime
los tipos de las rutas, que se definen dentro de create_app (dependencias locales).
"""

from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from loganalyzer import __version__, analytics
from loganalyzer.config import Settings, get_settings
from loganalyzer.models import Severity
from loganalyzer.pipeline import incident_to_dict
from loganalyzer.storage import init_db, make_engine, make_session_factory
from loganalyzer.storage import repository as repo
from loganalyzer.storage.orm import EventRow, IncidentRow

STATIC_DIR = Path(__file__).parent / "static"


class AckRequest(BaseModel):
    by: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=2000)


def _records(df: pd.DataFrame) -> list[dict[str, Any]]:
    out = []
    for row in df.to_dict(orient="records"):
        out.append(
            {
                k: (v.isoformat() if isinstance(v, pd.Timestamp | datetime) else v)
                for k, v in row.items()
            }
        )
    return out


def _event_dict(row: EventRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "timestamp": row.timestamp.isoformat(),
        "host": row.host,
        "source": row.source,
        "severity": row.severity,
        "category": row.category,
        "message": row.message,
        "signature": row.signature,
        "fields": row.fields or {},
    }


def create_app(
    settings: Settings | None = None,
    session_factory: sessionmaker[Session] | None = None,
    start_scheduler: bool = False,
) -> FastAPI:
    settings = settings or get_settings()
    if session_factory is None:
        engine = make_engine(settings.database_url)
        init_db(engine)
        session_factory = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        scheduler = None
        if start_scheduler:
            from loganalyzer.scheduler import build_scheduler

            scheduler = build_scheduler(settings, session_factory)
            scheduler.start()
        yield
        if scheduler is not None:
            scheduler.shutdown(wait=False)

    app = FastAPI(
        title="Centralized Log Analyzer",
        version=__version__,
        description="Búsqueda de eventos, estadísticas e incidentes.",
        lifespan=lifespan,
    )
    app.state.session_factory = session_factory

    def get_session(request: Request) -> Iterator[Session]:
        with request.app.state.session_factory() as session:
            yield session

    SessionDep = Annotated[Session, Depends(get_session)]
    HoursQ = Annotated[int, Query(ge=1, le=24 * 30)]

    def window(hours: int) -> datetime:
        return datetime.now(UTC) - timedelta(hours=hours)

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    def health(session: SessionDep) -> dict[str, str]:
        session.execute(text("SELECT 1"))
        return {"status": "ok", "version": __version__}

    @app.get("/api/meta")
    def meta(session: SessionDep) -> dict[str, list[str]]:
        return {
            "hosts": repo.distinct_values(session, "host"),
            "sources": repo.distinct_values(session, "source"),
            "categories": repo.distinct_values(session, "category"),
            "severities": [s.value for s in Severity],
        }

    @app.get("/api/events")
    def search(
        session: SessionDep,
        host: str | None = None,
        source: str | None = None,
        category: str | None = None,
        severity: Severity | None = None,
        min_severity: Severity | None = None,
        src_ip: str | None = None,
        signature: str | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        flt = repo.EventFilter(
            host=host,
            source=source,
            category=category,
            severity=severity.value if severity else None,
            min_severity=min_severity.value if min_severity else None,
            src_ip=src_ip,
            signature=signature,
            text=q,
            since=since,
            until=until,
        )
        total, rows = repo.search_events(session, flt, limit=limit, offset=offset)
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [_event_dict(r) for r in rows],
        }

    @app.get("/api/stats/summary")
    def summary(session: SessionDep, hours: HoursQ = 24) -> dict[str, Any]:
        since = window(hours)

        def count_by(column: Any) -> dict[str, int]:
            stmt = (
                select(column, func.count(EventRow.id))
                .where(EventRow.timestamp >= since)
                .group_by(column)
            )
            return {str(k): int(v) for k, v in session.execute(stmt)}

        open_incidents = session.scalar(
            select(func.count(IncidentRow.id)).where(IncidentRow.status == "open")
        )
        by_severity = count_by(EventRow.severity)
        return {
            "hours": hours,
            "total_events": sum(by_severity.values()),
            "by_severity": by_severity,
            "by_category": count_by(EventRow.category),
            "by_host": count_by(EventRow.host),
            "open_incidents": int(open_incidents or 0),
        }

    @app.get("/api/stats/errors-per-hour")
    def errors_per_hour(session: SessionDep, hours: HoursQ = 24) -> dict[str, Any]:
        pivot = analytics.errors_per_host_per_hour(
            repo.events_dataframe(session, since=window(hours))
        )
        if pivot.empty:
            return {"labels": [], "series": []}
        return {
            "labels": [ts.isoformat() for ts in pivot.index],
            "series": [{"host": h, "data": pivot[h].tolist()} for h in pivot.columns],
        }

    @app.get("/api/stats/top-signatures")
    def top_signatures(
        session: SessionDep, hours: HoursQ = 24, limit: Annotated[int, Query(ge=1, le=100)] = 10
    ) -> list[dict[str, Any]]:
        df = repo.events_dataframe(session, since=window(hours))
        return _records(analytics.top_errors(df, limit))

    @app.get("/api/stats/top-ips")
    def top_ips(
        session: SessionDep, hours: HoursQ = 24, limit: Annotated[int, Query(ge=1, le=100)] = 10
    ) -> list[dict[str, Any]]:
        df = repo.events_dataframe(session, since=window(hours))
        return _records(analytics.top_offending_ips(df, limit))

    @app.get("/api/stats/new-signatures")
    def new_signatures(
        session: SessionDep,
        recent_hours: HoursQ = 24,
        baseline_days: Annotated[int, Query(ge=1, le=90)] = 7,
    ) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        recent = timedelta(hours=recent_hours)
        baseline = timedelta(days=baseline_days)
        df = repo.events_dataframe(session, since=now - recent - baseline)
        return _records(analytics.new_signatures(df, now=now, recent=recent, baseline=baseline))

    @app.get("/api/incidents")
    def incidents(
        session: SessionDep,
        status: Annotated[str | None, Query(pattern="^(open|acknowledged|resolved)$")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, Any]]:
        return [incident_to_dict(r) for r in repo.list_incidents(session, status, limit)]

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: int, session: SessionDep) -> dict[str, Any]:
        row = session.get(IncidentRow, incident_id)
        if row is None:
            raise HTTPException(404, "incidente no encontrado")
        return incident_to_dict(row)

    @app.post("/api/incidents/{incident_id}/ack")
    def ack(incident_id: int, body: AckRequest, session: SessionDep) -> dict[str, Any]:
        row = repo.set_incident_status(session, incident_id, "acknowledged", body.by, body.note)
        if row is None:
            raise HTTPException(404, "incidente no encontrado")
        session.commit()
        return incident_to_dict(row)

    @app.post("/api/incidents/{incident_id}/resolve")
    def resolve(incident_id: int, session: SessionDep) -> dict[str, Any]:
        row = repo.set_incident_status(session, incident_id, "resolved")
        if row is None:
            raise HTTPException(404, "incidente no encontrado")
        session.commit()
        return incident_to_dict(row)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app

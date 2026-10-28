"""Acceso a datos. Todas las funciones reciben una Session y no hacen commit,
así el llamador decide el límite de la transacción (ej. eventos + offset juntos)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from loganalyzer.models import IncidentCandidate, IncidentSeverity, LogEvent, Severity
from loganalyzer.signatures import normalize_message, signature_of
from loganalyzer.storage.orm import CollectorStateRow, EventRow, IncidentRow

_INCIDENT_RANK = {s: i for i, s in enumerate(IncidentSeverity)}


# ---------------------------------------------------------------- eventos


def event_to_row(event: LogEvent) -> EventRow:
    template = normalize_message(event.message)
    return EventRow(
        timestamp=event.timestamp,
        host=event.host,
        source=event.source,
        severity=event.severity.value,
        severity_level=event.severity.level,
        category=event.category,
        message=event.message,
        signature=signature_of(event.message, event.category),
        template=template[:1000],
        src_ip=event.fields.get("src_ip"),
        fields=event.fields,
    )


def row_to_event(row: EventRow) -> LogEvent:
    return LogEvent(
        timestamp=row.timestamp,
        host=row.host,
        source=row.source,
        severity=Severity(row.severity),
        category=row.category,
        message=row.message,
        fields=row.fields or {},
    )


def add_events(session: Session, events: Iterable[LogEvent]) -> int:
    rows = [event_to_row(e) for e in events]
    session.add_all(rows)
    return len(rows)


@dataclass
class EventFilter:
    host: str | None = None
    source: str | None = None
    category: str | None = None
    severity: str | None = None
    min_severity: str | None = None
    signature: str | None = None
    src_ip: str | None = None
    text: str | None = None
    since: datetime | None = None
    until: datetime | None = None

    def apply(self, stmt: Select[Any]) -> Select[Any]:
        if self.host:
            stmt = stmt.where(EventRow.host == self.host)
        if self.source:
            stmt = stmt.where(EventRow.source == self.source)
        if self.category:
            stmt = stmt.where(EventRow.category == self.category)
        if self.severity:
            stmt = stmt.where(EventRow.severity == self.severity)
        if self.min_severity:
            stmt = stmt.where(EventRow.severity_level >= Severity(self.min_severity).level)
        if self.signature:
            stmt = stmt.where(EventRow.signature == self.signature)
        if self.src_ip:
            stmt = stmt.where(EventRow.src_ip == self.src_ip)
        if self.text:
            pattern = f"%{self.text}%"
            stmt = stmt.where(or_(EventRow.message.ilike(pattern), EventRow.host.ilike(pattern)))
        if self.since:
            stmt = stmt.where(EventRow.timestamp >= self.since)
        if self.until:
            stmt = stmt.where(EventRow.timestamp < self.until)
        return stmt


def search_events(
    session: Session, flt: EventFilter, limit: int = 100, offset: int = 0
) -> tuple[int, Sequence[EventRow]]:
    total = session.scalar(flt.apply(select(func.count(EventRow.id)))) or 0
    stmt = flt.apply(select(EventRow)).order_by(EventRow.timestamp.desc(), EventRow.id.desc())
    rows = session.scalars(stmt.limit(limit).offset(offset)).all()
    return total, rows


def load_events(session: Session, since: datetime, until: datetime | None = None) -> list[LogEvent]:
    flt = EventFilter(since=since, until=until)
    stmt = flt.apply(select(EventRow)).order_by(EventRow.timestamp)
    return [row_to_event(r) for r in session.scalars(stmt)]


_DF_COLUMNS = [
    "id", "timestamp", "host", "source", "severity", "severity_level",
    "category", "message", "signature", "template", "src_ip", "status",
]  # fmt: skip


def events_dataframe(
    session: Session, since: datetime | None = None, until: datetime | None = None
) -> pd.DataFrame:
    """Carga eventos en un DataFrame liviano (sin el JSON completo de fields)."""
    flt = EventFilter(since=since, until=until)
    stmt = flt.apply(
        select(
            EventRow.id,
            EventRow.timestamp,
            EventRow.host,
            EventRow.source,
            EventRow.severity,
            EventRow.severity_level,
            EventRow.category,
            EventRow.message,
            EventRow.signature,
            EventRow.template,
            EventRow.src_ip,
            EventRow.fields,
        )
    )
    records = []
    for row in session.execute(stmt):
        data = row._asdict()
        fields = data.pop("fields") or {}
        data["status"] = fields.get("status") if isinstance(fields.get("status"), int) else None
        records.append(data)
    df = pd.DataFrame.from_records(records, columns=_DF_COLUMNS)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def distinct_values(session: Session, column: str) -> list[str]:
    col = getattr(EventRow, column)
    return [v for v in session.scalars(select(col).distinct().order_by(col)) if v]


# ---------------------------------------------------------------- estado de collectors


def get_state(session: Session, key: str) -> CollectorStateRow | None:
    return session.get(CollectorStateRow, key)


def save_state(
    session: Session,
    key: str,
    host: str,
    *,
    offset: int = 0,
    inode: str | None = None,
    cursor: str | None = None,
) -> None:
    row = session.get(CollectorStateRow, key)
    if row is None:
        row = CollectorStateRow(key=key, host=host)
        session.add(row)
    row.offset = offset
    row.inode = inode
    row.cursor = cursor
    row.updated_at = datetime.now(UTC)


# ---------------------------------------------------------------- incidentes


def upsert_incidents(
    session: Session, candidates: Iterable[IncidentCandidate]
) -> list[IncidentRow]:
    """Persiste candidatos aplicando dedup. Devuelve solo los incidentes nuevos
    (los que hay que notificar).

    Un candidato se fusiona con un incidente no resuelto de la misma dedup_key si
    su actividad empieza antes de que venza el cooldown del incidente existente.
    Re-evaluar la misma ventana es idempotente: no crea duplicados ni infla contadores.
    """
    created: list[IncidentRow] = []
    now = datetime.now(UTC)
    for cand in candidates:
        existing = session.scalars(
            select(IncidentRow)
            .where(IncidentRow.dedup_key == cand.dedup_key, IncidentRow.status != "resolved")
            .order_by(IncidentRow.last_seen.desc())
            .limit(1)
        ).first()
        cooldown = timedelta(minutes=cand.cooldown_minutes)
        if existing is not None and cand.first_seen <= existing.last_seen + cooldown:
            if cand.last_seen > existing.last_seen:
                existing.last_seen = cand.last_seen
                existing.occurrences += 1
                existing.updated_at = now
            existing.first_seen = min(existing.first_seen, cand.first_seen)
            existing.count = max(existing.count, cand.count)
            if (
                _INCIDENT_RANK[IncidentSeverity(cand.severity)]
                > _INCIDENT_RANK[IncidentSeverity(existing.severity)]
            ):
                existing.severity = cand.severity.value
            existing.context = {**(existing.context or {}), **cand.context}
            continue

        row = IncidentRow(
            rule_id=cand.rule_id,
            dedup_key=cand.dedup_key,
            title=cand.title,
            description=cand.description,
            severity=cand.severity.value,
            host=cand.host,
            status="open",
            first_seen=cand.first_seen,
            last_seen=cand.last_seen,
            count=cand.count,
            occurrences=1,
            context=cand.context,
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()  # necesitamos el id para la notificación
        created.append(row)
    return created


def list_incidents(
    session: Session, status: str | None = None, limit: int = 100
) -> Sequence[IncidentRow]:
    stmt = select(IncidentRow)
    if status:
        stmt = stmt.where(IncidentRow.status == status)
    stmt = stmt.order_by(IncidentRow.last_seen.desc()).limit(limit)
    return session.scalars(stmt).all()


def set_incident_status(
    session: Session, incident_id: int, status: str, by: str | None = None, note: str | None = None
) -> IncidentRow | None:
    row = session.get(IncidentRow, incident_id)
    if row is None:
        return None
    row.status = status
    row.updated_at = datetime.now(UTC)
    if status == "acknowledged":
        row.acked_at = row.updated_at
        row.acked_by = by
        row.ack_note = note
    return row

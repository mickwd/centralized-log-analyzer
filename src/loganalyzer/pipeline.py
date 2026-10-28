"""Orquestación: recolectar -> guardar -> detectar -> notificar."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from loganalyzer.collectors import Collector, StoredState, build_collector
from loganalyzer.config import HostConfig, Inventory, Settings
from loganalyzer.notifiers import Notifier, dispatch
from loganalyzer.rules import Rule, evaluate
from loganalyzer.storage import repository as repo
from loganalyzer.storage.orm import IncidentRow

log = logging.getLogger(__name__)


@dataclass
class HostReport:
    host: str
    events: int = 0
    lines: int = 0
    unparsed: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DetectionReport:
    evaluated_events: int
    candidates: int
    new_incidents: list[dict[str, Any]]
    notification_errors: list[str] = field(default_factory=list)


def incident_to_dict(row: IncidentRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "rule_id": row.rule_id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "host": row.host,
        "status": row.status,
        "first_seen": row.first_seen.isoformat(),
        "last_seen": row.last_seen.isoformat(),
        "count": row.count,
        "occurrences": row.occurrences,
        "context": row.context or {},
        "acked_by": row.acked_by,
        "acked_at": row.acked_at.isoformat() if row.acked_at else None,
        "ack_note": row.ack_note,
    }


def collect_host(
    host: HostConfig,
    session_factory: sessionmaker[Session],
    collector: Collector | None = None,
    chunk_size: int = 1024 * 1024,
) -> HostReport:
    """Recolecta un host. Eventos y offsets se guardan en la misma transacción:
    si algo falla no avanza el offset y la próxima corrida reintenta (at-least-once
    sin duplicar lo ya confirmado)."""
    report = HostReport(host=host.name)
    collector = collector or build_collector(host, chunk_size=chunk_size)
    with session_factory() as session:

        def lookup(key: str) -> StoredState | None:
            row = repo.get_state(session, key)
            if row is None:
                return None
            return StoredState(offset=row.offset, inode=row.inode, cursor=row.cursor)

        result = collector.collect(lookup)
        report.events = repo.add_events(session, result.events)
        for st in result.states:
            repo.save_state(
                session, st.key, st.host, offset=st.offset, inode=st.inode, cursor=st.cursor
            )
        session.commit()
    report.lines = result.lines_read
    report.unparsed = result.unparsed
    report.errors = result.errors
    report.notes = result.notes
    return report


def run_collection(
    inventory: Inventory,
    session_factory: sessionmaker[Session],
    settings: Settings,
    only_hosts: list[str] | None = None,
    collector_factory: Callable[[HostConfig], Collector] | None = None,
) -> list[HostReport]:
    reports = []
    for host in inventory.hosts:
        if not host.enabled or (only_hosts and host.name not in only_hosts):
            continue
        try:
            collector = collector_factory(host) if collector_factory else None
            report = collect_host(
                host, session_factory, collector, chunk_size=settings.max_bytes_per_read
            )
        except Exception as exc:
            # Un host caído (timeout SSH, credenciales) no debe frenar al resto
            log.exception("falló la recolección de %s", host.name)
            report = HostReport(host=host.name, errors=[f"{type(exc).__name__}: {exc}"])
        reports.append(report)
    return reports


def run_detection(
    rules: list[Rule],
    session_factory: sessionmaker[Session],
    notifiers: list[Notifier],
    since: datetime | None = None,
    until: datetime | None = None,
    lookback: timedelta = timedelta(minutes=60),
) -> DetectionReport:
    since = since or datetime.now(UTC) - lookback
    with session_factory() as session:
        events = repo.load_events(session, since, until)
        candidates = evaluate(rules, events)
        created = repo.upsert_incidents(session, candidates)
        session.commit()
        new = [incident_to_dict(r) for r in created]

    errors: list[str] = []
    for incident in new:
        errors.extend(dispatch(notifiers, incident))
    return DetectionReport(len(events), len(candidates), new, errors)

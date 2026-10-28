"""Ejecución periódica de recolección + detección con APScheduler."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler
from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy.orm import Session, sessionmaker

from loganalyzer.config import Settings, load_inventory
from loganalyzer.notifiers import build_notifiers
from loganalyzer.pipeline import run_collection, run_detection
from loganalyzer.rules import load_rules

log = logging.getLogger(__name__)


def run_cycle(settings: Settings, session_factory: sessionmaker[Session]) -> None:
    # Se releen inventario y reglas en cada ciclo: cambios en YAML sin reiniciar
    inventory = load_inventory(settings.inventory_path)
    rules = load_rules(settings.rules_path)
    reports = run_collection(inventory, session_factory, settings)
    total = sum(r.events for r in reports)
    failed = [r.host for r in reports if r.errors]
    detection = run_detection(
        rules,
        session_factory,
        build_notifiers(settings),
        lookback=timedelta(minutes=settings.detection_lookback_minutes),
    )
    log.info(
        "ciclo ok: %d eventos nuevos, %d incidentes nuevos, hosts con error: %s",
        total,
        len(detection.new_incidents),
        failed or "ninguno",
    )


def build_scheduler(
    settings: Settings, session_factory: sessionmaker[Session], blocking: bool = False
) -> BaseScheduler:
    scheduler: BaseScheduler = BlockingScheduler() if blocking else BackgroundScheduler()
    scheduler.add_job(
        run_cycle,
        "interval",
        minutes=settings.schedule_minutes,
        args=[settings, session_factory],
        id="collect_and_detect",
        max_instances=1,  # si un ciclo tarda más que el intervalo no se pisan
        coalesce=True,
        next_run_time=datetime.now(UTC),  # primera corrida inmediata
    )
    return scheduler

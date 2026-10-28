"""Tablas SQLAlchemy 2.0. Compatibles con PostgreSQL (producción) y SQLite (dev/tests)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    TypeDecorator,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class UTCDateTime(TypeDecorator[datetime]):
    """Guarda siempre en UTC y devuelve datetimes aware (SQLite pierde la zona)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        # SQLite compara como texto: guardamos naive UTC para que el orden sea correcto
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


JsonType = JSON().with_variant(JSONB(), "postgresql")
# BIGINT en Postgres; en SQLite solo INTEGER PRIMARY KEY es autoincremental
BigId = BigInteger().with_variant(Integer(), "sqlite")


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    severity_level: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(String(16), nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(64))
    fields: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    ingested_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=lambda: datetime.now(UTC), nullable=False
    )

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_host_timestamp", "host", "timestamp"),
        Index("ix_events_category_timestamp", "category", "timestamp"),
        Index("ix_events_severity_timestamp", "severity_level", "timestamp"),
        Index("ix_events_signature", "signature"),
        Index("ix_events_src_ip", "src_ip"),
    )


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=lambda: datetime.now(UTC), nullable=False
    )
    acked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    acked_by: Mapped[str | None] = mapped_column(String(128))
    ack_note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_incidents_dedup", "dedup_key", "last_seen"),
        Index("ix_incidents_status", "status", "last_seen"),
    )


class CollectorStateRow(Base):
    """Posición de lectura por fuente: offset+inode para archivos, cursor para journald,
    último RecordId para canales de Windows."""

    __tablename__ = "collector_state"

    key: Mapped[str] = mapped_column(String(512), primary_key=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    offset: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    inode: Mapped[str | None] = mapped_column(String(64))
    cursor: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=lambda: datetime.now(UTC), nullable=False
    )

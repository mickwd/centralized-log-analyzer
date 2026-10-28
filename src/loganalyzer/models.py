"""Modelo común de eventos e incidentes.

Todos los parsers devuelven un LogEvent sin importar el origen (syslog, nginx,
journald, Windows). Así las reglas y la analítica trabajan sobre un único esquema.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        return _SEVERITY_LEVELS[self]

    @classmethod
    def from_syslog(cls, code: int) -> Severity:
        """Convierte la severidad numérica de syslog (0 emerg ... 7 debug)."""
        if code <= 2:
            return cls.CRITICAL
        if code == 3:
            return cls.ERROR
        if code == 4:
            return cls.WARNING
        if code == 5:
            return cls.NOTICE
        if code == 6:
            return cls.INFO
        return cls.DEBUG


_SEVERITY_LEVELS = {
    Severity.DEBUG: 10,
    Severity.INFO: 20,
    Severity.NOTICE: 25,
    Severity.WARNING: 30,
    Severity.ERROR: 40,
    Severity.CRITICAL: 50,
}


class Category(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    ACCOUNT_LOCKOUT = "account_lockout"
    HTTP_ACCESS = "http_access"
    HTTP_ERROR = "http_error"
    SERVICE_CRASH = "service_crash"
    SERVICE_RESTART = "service_restart"
    UNEXPECTED_SHUTDOWN = "unexpected_shutdown"
    APPLICATION_ERROR = "application_error"
    SYSTEM = "system"


class IncidentSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def ensure_utc(value: datetime) -> datetime:
    """Los timestamps sin zona se asumen UTC; los demás se convierten a UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class LogEvent(BaseModel):
    model_config = ConfigDict(frozen=False)

    timestamp: datetime
    host: str
    source: str
    severity: Severity = Severity.INFO
    category: str = Category.SYSTEM.value
    message: str
    fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def field(self, path: str) -> Any:
        """Resuelve rutas tipo 'host' o 'fields.src_ip' (usado por las reglas)."""
        if path.startswith("fields."):
            return self.fields.get(path.removeprefix("fields."))
        return getattr(self, path, None)


class IncidentCandidate(BaseModel):
    """Resultado del motor de reglas antes de persistirse y deduplicarse."""

    rule_id: str
    dedup_key: str
    title: str
    description: str = ""
    severity: IncidentSeverity
    host: str | None = None
    first_seen: datetime
    last_seen: datetime
    count: int
    context: dict[str, Any] = Field(default_factory=dict)
    cooldown_minutes: int = 60

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

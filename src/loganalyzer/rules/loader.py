"""Definición de reglas en YAML y su validación."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from loganalyzer.models import IncidentSeverity, LogEvent, Severity

_DURATION = re.compile(r"^\s*(?P<n>\d+)\s*(?P<unit>s|m|h|d)\s*$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(value: str | int | timedelta) -> timedelta:
    """'30s', '5m', '2h', '1d'. Un entero se interpreta como minutos."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, int):
        return timedelta(minutes=value)
    m = _DURATION.match(value)
    if m is None:
        raise ValueError(f"duración inválida: {value!r} (usar 30s, 5m, 2h, 1d)")
    return timedelta(**{_UNITS[m["unit"]]: int(m["n"])})


def _as_list(value: Any) -> list[Any] | None:
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


class EventMatcher(BaseModel):
    """Filtro declarativo. Todos los criterios presentes deben cumplirse (AND)."""

    category: list[str] | None = None
    source: list[str] | None = None
    host: list[str] | None = None
    min_severity: Severity | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    field_gte: dict[str, float] = Field(default_factory=dict)
    message_regex: str | None = None

    _regex: re.Pattern[str] | None = None

    @field_validator("category", "source", "host", mode="before")
    @classmethod
    def _listify(cls, value: Any) -> list[str] | None:
        return _as_list(value)

    def model_post_init(self, _context: Any) -> None:
        self._regex = re.compile(self.message_regex) if self.message_regex else None

    def matches(self, event: LogEvent) -> bool:
        if self.category and event.category not in self.category:
            return False
        if self.source and event.source not in self.source:
            return False
        if self.host and event.host not in self.host:
            return False
        if self.min_severity and event.severity.level < self.min_severity.level:
            return False
        for key, expected in self.fields.items():
            actual = event.fields.get(key)
            allowed = expected if isinstance(expected, list) else [expected]
            if actual not in allowed:
                return False
        for key, minimum in self.field_gte.items():
            actual = event.fields.get(key)
            if not isinstance(actual, int | float) or actual < minimum:
                return False
        return not (self._regex and not self._regex.search(event.message))


class Rule(BaseModel):
    id: str
    type: Literal["threshold", "repeated_signature", "match", "ratio"]
    title: str
    description: str = ""
    severity: IncidentSeverity
    enabled: bool = True
    filter: EventMatcher = Field(default_factory=EventMatcher)
    group_by: list[str] = Field(default_factory=list)
    window: timedelta = timedelta(minutes=5)
    min_count: int = 1
    cooldown: timedelta = timedelta(minutes=60)
    # Solo para type=ratio: eventos que forman el total (ej. todos los requests)
    denominator: EventMatcher | None = None
    min_ratio: float | None = None

    @field_validator("window", "cooldown", mode="before")
    @classmethod
    def _duration(cls, value: Any) -> timedelta:
        return parse_duration(value)

    @model_validator(mode="after")
    def _check_type(self) -> Rule:
        if self.type == "ratio" and (self.denominator is None or self.min_ratio is None):
            raise ValueError(f"regla {self.id}: type=ratio requiere 'denominator' y 'min_ratio'")
        if self.min_count < 1:
            raise ValueError(f"regla {self.id}: min_count debe ser >= 1")
        return self


class RuleSet(BaseModel):
    rules: list[Rule]

    @model_validator(mode="after")
    def _unique_ids(self) -> RuleSet:
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("hay ids de regla repetidos")
        return self


def load_rules(path: str | Path) -> list[Rule]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return [r for r in RuleSet(rules=data.get("rules", [])).rules if r.enabled]

"""Registro de parsers por formato.

Cada formato se mapea a una función pura `(line, ctx) -> LogEvent | None`.
Los collectors solo conocen el nombre del formato configurado en el inventario.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo

from loganalyzer.models import LogEvent
from loganalyzer.parsers.journald import parse_journald_json
from loganalyzer.parsers.nginx import parse_nginx_access, parse_nginx_error
from loganalyzer.parsers.syslog import parse_syslog_line
from loganalyzer.parsers.windows import parse_windows_event


@dataclass(frozen=True)
class ParseContext:
    host: str
    tz: tzinfo = UTC
    now: datetime = field(default_factory=lambda: datetime.now(UTC))


Parser = Callable[[str, ParseContext], LogEvent | None]

PARSERS: dict[str, Parser] = {
    "auth": lambda line, ctx: parse_syslog_line(
        line, host=ctx.host, source="auth", tz=ctx.tz, now=ctx.now
    ),
    "syslog": lambda line, ctx: parse_syslog_line(
        line, host=ctx.host, source="syslog", tz=ctx.tz, now=ctx.now
    ),
    "nginx_access": lambda line, ctx: parse_nginx_access(line, host=ctx.host),
    "nginx_error": lambda line, ctx: parse_nginx_error(line, host=ctx.host, tz=ctx.tz),
    "journald_json": lambda line, ctx: parse_journald_json(line, host=ctx.host),
    "windows_json": lambda line, ctx: parse_windows_event(line, host=ctx.host),
}


def get_parser(fmt: str) -> Parser:
    try:
        return PARSERS[fmt]
    except KeyError as exc:
        known = ", ".join(sorted(PARSERS))
        raise ValueError(f"formato desconocido '{fmt}' (soportados: {known})") from exc


__all__ = ["PARSERS", "ParseContext", "Parser", "get_parser"]

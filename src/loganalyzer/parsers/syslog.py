"""Parser de syslog RFC3164 (BSD) y RFC5424.

RFC3164 no trae año ni zona horaria, así que el año se infiere a partir de una
fecha de referencia (`now`) y la zona se toma de la configuración del host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo

from loganalyzer.models import LogEvent, Severity
from loganalyzer.parsers.common import classify

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<tag>[^:\[\s]+)(?:\[(?P<pid>[^\]]+)\])?: ?(?P<msg>.*)$"
)

# Variante "traditional" de rsyslog con timestamp RFC3339 (ej. Debian 12+).
_ISO_TRADITIONAL = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    r"(?P<host>\S+) (?P<tag>[^:\[\s]+)(?:\[(?P<pid>[^\]]+)\])?: ?(?P<msg>.*)$"
)

_RFC5424_HEADER = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$"
)
_SD_PARAM = re.compile(r'(?P<name>[^\s=\]"]+)="(?P<value>(?:[^"\\]|\\.)*)"')


@dataclass
class SyslogRecord:
    timestamp: datetime
    hostname: str
    app: str | None
    pid: str | None
    message: str
    facility: int | None = None
    severity_code: int | None = None
    msgid: str | None = None
    structured_data: dict[str, dict[str, str]] = field(default_factory=dict)


def _split_pri(pri: str | None) -> tuple[int | None, int | None]:
    if pri is None:
        return None, None
    value = int(pri)
    return value // 8, value % 8


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _infer_year(month: int, day: int, clock: str, tz: tzinfo, now: datetime) -> datetime:
    hh, mm, ss = (int(x) for x in clock.split(":"))
    local_now = now.astimezone(tz)
    candidate = datetime(local_now.year, month, day, hh, mm, ss, tzinfo=tz)
    # Un log de diciembre leído en enero pertenece al año anterior.
    if candidate - local_now > timedelta(days=2):
        candidate = candidate.replace(year=local_now.year - 1)
    return candidate


def parse_rfc3164(
    line: str, *, tz: tzinfo = UTC, now: datetime | None = None
) -> SyslogRecord | None:
    line = line.rstrip("\r\n")
    now = now or datetime.now(UTC)
    try:
        if (m := _RFC3164.match(line)) and m["mon"] in _MONTHS:
            facility, sev = _split_pri(m["pri"])
            ts = _infer_year(_MONTHS[m["mon"]], int(m["day"]), m["time"], tz, now)
            return SyslogRecord(ts, m["host"], m["tag"], m["pid"], m["msg"], facility, sev)
        if m := _ISO_TRADITIONAL.match(line):
            facility, sev = _split_pri(m["pri"])
            ts = _parse_iso(m["ts"])
            return SyslogRecord(ts, m["host"], m["tag"], m["pid"], m["msg"], facility, sev)
    except ValueError:  # fecha imposible (ej. "Feb 30")
        return None
    return None


def _parse_structured_data(rest: str) -> tuple[dict[str, dict[str, str]], str]:
    """Separa el bloque STRUCTURED-DATA del mensaje respetando los escapes \\] y \\"."""
    if rest.startswith("-"):
        return {}, rest[2:] if len(rest) > 1 else ""
    data: dict[str, dict[str, str]] = {}
    i = 0
    while i < len(rest) and rest[i] == "[":
        j = i + 1
        in_quotes = False
        while j < len(rest):
            ch = rest[j]
            if ch == "\\":
                j += 2
                continue
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == "]" and not in_quotes:
                break
            j += 1
        element = rest[i + 1 : j]
        sd_id, _, params = element.partition(" ")
        data[sd_id] = {
            p["name"]: re.sub(r"\\(.)", r"\1", p["value"]) for p in _SD_PARAM.finditer(params)
        }
        i = j + 1
    return data, rest[i:].lstrip(" ")


def parse_rfc5424(line: str) -> SyslogRecord | None:
    line = line.rstrip("\r\n")
    m = _RFC5424_HEADER.match(line)
    if m is None or m["ts"] == "-":
        return None
    try:
        ts = _parse_iso(m["ts"])
    except ValueError:
        return None
    facility, sev = _split_pri(m["pri"])
    sd, msg = _parse_structured_data(m["rest"])
    msg = msg.removeprefix("﻿")  # BOM opcional que define la RFC

    def nil(value: str) -> str | None:
        return None if value == "-" else value

    return SyslogRecord(
        ts, m["host"], nil(m["app"]), nil(m["procid"]), msg, facility, sev, nil(m["msgid"]), sd
    )


def parse_syslog_line(
    line: str,
    *,
    host: str | None = None,
    source: str = "syslog",
    tz: tzinfo = UTC,
    now: datetime | None = None,
) -> LogEvent | None:
    """Detecta el formato, parsea y clasifica. Devuelve None para líneas vacías o inválidas."""
    if not line.strip():
        return None
    record = parse_rfc5424(line) if _RFC5424_HEADER.match(line) else None
    if record is None:
        record = parse_rfc3164(line, tz=tz, now=now)
    if record is None:
        return None

    explicit = (
        Severity.from_syslog(record.severity_code) if record.severity_code is not None else None
    )
    result = classify(record.app, record.message, explicit)
    fields = dict(result.fields)
    fields["program"] = record.app
    if record.pid:
        fields["pid"] = record.pid
    if record.msgid:
        fields["msgid"] = record.msgid
    if record.structured_data:
        fields["sd"] = record.structured_data
    if record.facility is not None:
        fields["facility"] = record.facility

    return LogEvent(
        timestamp=record.timestamp,
        host=host or record.hostname,
        source=source,
        severity=result.severity,
        category=result.category,
        message=record.message,
        fields=fields,
    )

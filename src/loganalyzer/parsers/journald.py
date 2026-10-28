"""Parser de `journalctl -o json` (un objeto JSON por línea)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from loganalyzer.models import LogEvent, Severity
from loganalyzer.parsers.common import classify


def _decode_message(raw: Any) -> str:
    # journald serializa los mensajes no UTF-8 como lista de bytes
    if isinstance(raw, list):
        return bytes(int(b) for b in raw).decode("utf-8", errors="replace")
    return "" if raw is None else str(raw)


def parse_journald_json(line: str | dict[str, Any], *, host: str | None = None) -> LogEvent | None:
    if isinstance(line, str):
        if not line.strip():
            return None
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None
    else:
        entry = line
    if not isinstance(entry, dict) or "__REALTIME_TIMESTAMP" not in entry:
        return None

    micros = int(entry["__REALTIME_TIMESTAMP"])
    ts = datetime.fromtimestamp(micros / 1_000_000, tz=UTC)
    message = _decode_message(entry.get("MESSAGE"))
    app = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    priority = entry.get("PRIORITY")
    explicit = Severity.from_syslog(int(priority)) if priority not in (None, "") else None

    result = classify(app, message, explicit)
    fields = dict(result.fields)
    fields["program"] = app
    for key, name in (("_SYSTEMD_UNIT", "unit"), ("_PID", "pid"), ("__CURSOR", "cursor")):
        if entry.get(key):
            fields[name] = entry[key]

    return LogEvent(
        timestamp=ts,
        host=host or entry.get("_HOSTNAME", "unknown"),
        source="journald",
        severity=result.severity,
        category=result.category,
        message=message,
        fields=fields,
    )

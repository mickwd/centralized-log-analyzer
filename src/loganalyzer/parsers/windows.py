"""Parser de eventos de Windows exportados como JSON.

El collector WinRM ejecuta Get-WinEvent y serializa cada evento con sus campos
de EventData por nombre (TargetUserName, IpAddress, param1...), que es más
estable que depender del orden de Properties entre versiones de Windows.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from loganalyzer.models import Category, LogEvent, Severity

_MS_DATE = re.compile(r"/Date\((?P<ms>-?\d+)(?:[+-]\d{4})?\)/")

# Niveles de Windows: 1 Critical, 2 Error, 3 Warning, 4 Information, 0 LogAlways
_LEVELS = {1: Severity.CRITICAL, 2: Severity.ERROR, 3: Severity.WARNING, 4: Severity.INFO}

_LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network_cleartext",
    "10": "remote_interactive",
    "11": "cached_interactive",
}


def parse_windows_timestamp(value: Any) -> datetime:
    """Acepta ISO 8601 (con 7 decimales de .NET) y el formato /Date(ms)/ de PowerShell 5.1."""
    if isinstance(value, datetime):
        return value
    text = str(value)
    if m := _MS_DATE.fullmatch(text):
        return datetime.fromtimestamp(int(m["ms"]) / 1000, tz=UTC)
    text = text.replace("Z", "+00:00")
    # .NET usa 7 decimales; fromisoformat de 3.11 acepta hasta 6
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    return datetime.fromisoformat(text)


def _clean(value: Any) -> Any:
    """Windows usa "-" para campos vacíos (ej. IpAddress en logons locales)."""
    return None if value in (None, "", "-") else value


def _logon_fields(data: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "user": _clean(data.get("TargetUserName")),
        "domain": _clean(data.get("TargetDomainName")),
        "src_ip": _clean(data.get("IpAddress")),
        "workstation": _clean(data.get("WorkstationName")),
    }
    logon_type = str(data.get("LogonType", "")).strip()
    if logon_type:
        fields["logon_type"] = _LOGON_TYPES.get(logon_type, logon_type)
    for key, name in (("Status", "status"), ("SubStatus", "sub_status")):
        if data.get(key):
            fields[name] = str(data[key]).lower()
    return {k: v for k, v in fields.items() if v is not None}


def _classify(
    event_id: int, log_name: str, level: int, data: dict[str, Any], provider: str
) -> tuple[str, Severity, dict[str, Any], str | None]:
    """Devuelve (categoría, severidad, campos, resumen). El resumen reemplaza al Message largo."""
    log = log_name.lower()
    if log == "security" and event_id == 4625:
        f = _logon_fields(data)
        summary = f"Failed logon for {f.get('user', '?')} from {f.get('src_ip', 'local')}"
        return Category.AUTH_FAILURE.value, Severity.WARNING, f, summary
    if log == "security" and event_id == 4624:
        f = _logon_fields(data)
        summary = f"Successful logon for {f.get('user', '?')} ({f.get('logon_type', '?')})"
        return Category.AUTH_SUCCESS.value, Severity.INFO, f, summary
    if log == "security" and event_id == 4740:
        f = {
            "user": _clean(data.get("TargetUserName")),
            "caller_computer": _clean(data.get("TargetDomainName")),
            "reported_by": _clean(data.get("SubjectUserName")),
        }
        f = {k: v for k, v in f.items() if v is not None}
        summary = (
            f"Account locked out: {f.get('user', '?')} (caller {f.get('caller_computer', '?')})"
        )
        return Category.ACCOUNT_LOCKOUT.value, Severity.WARNING, f, summary
    if log == "system" and event_id in (7031, 7034):
        f = {"service": data.get("param1")}
        if str(data.get("param2", "")).isdigit():
            f["crash_count"] = int(data["param2"])
        summary = f"Service {f['service']} terminated unexpectedly"
        return Category.SERVICE_CRASH.value, Severity.ERROR, f, summary
    if log == "system" and event_id == 6008:
        f = {"previous_shutdown": f"{data.get('param2', '')} {data.get('param1', '')}".strip()}
        return Category.UNEXPECTED_SHUTDOWN.value, Severity.CRITICAL, f, "Unexpected shutdown"

    severity = _LEVELS.get(level, Severity.INFO)
    category = (
        Category.APPLICATION_ERROR.value
        if severity.level >= Severity.ERROR.level
        else Category.SYSTEM.value
    )
    f = {}
    if provider == "Application Error" and data.get("param1"):
        f = {"faulting_app": data["param1"], "exception_code": data.get("param7")}
    return category, severity, {k: v for k, v in f.items() if v is not None}, None


def parse_windows_event(raw: str | dict[str, Any], *, host: str | None = None) -> LogEvent | None:
    if isinstance(raw, str):
        if not raw.strip():
            return None
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, dict) or "Id" not in raw or "TimeCreated" not in raw:
        return None

    event_id = int(raw["Id"])
    log_name = str(raw.get("LogName", ""))
    level = int(raw.get("Level") or 0)
    provider = str(raw.get("ProviderName", ""))
    data = raw.get("Data") or {}
    category, severity, fields, summary = _classify(event_id, log_name, level, data, provider)

    first_line = str(raw.get("Message") or "").strip().splitlines()
    message = summary or (first_line[0] if first_line else f"{provider} event {event_id}")
    fields.update(
        event_id=event_id,
        log_name=log_name,
        provider=provider,
        record_id=raw.get("RecordId"),
    )

    machine = str(raw.get("MachineName") or "unknown").split(".")[0].lower()
    return LogEvent(
        timestamp=parse_windows_timestamp(raw["TimeCreated"]),
        host=host or machine,
        source=f"windows_{log_name.lower()}",
        severity=severity,
        category=category,
        message=message,
        fields=fields,
    )

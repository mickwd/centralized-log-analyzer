"""Parser de nginx: access log en formato combined y error log."""

from __future__ import annotations

import re
from datetime import UTC, datetime, tzinfo

from loganalyzer.models import Category, LogEvent, Severity

# log_format combined '$remote_addr - $remote_user [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
# Se toleran campos extra al final (ej. $request_time) que agregan muchos equipos.
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referer>(?:[^"\\]|\\.)*)" '
    r'"(?P<ua>(?:[^"\\]|\\.)*)")?(?P<extra>.*)$'
)
_REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>HTTP/[\d.]+))?$")
_REQUEST_TIME = re.compile(r"(?:rt=)?(?P<rt>\d+\.\d{3})\b")

_ERROR = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
    r"(?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$"
)
_ERROR_KV = re.compile(
    r', (?P<key>client|server|request|upstream|host|referrer): "?(?P<value>[^",]*)"?'
)

_ERROR_LEVELS = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "notice": Severity.NOTICE,
    "warn": Severity.WARNING,
    "error": Severity.ERROR,
    "crit": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "emerg": Severity.CRITICAL,
}


def _status_severity(status: int) -> Severity:
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.NOTICE
    return Severity.INFO


def parse_nginx_access(line: str, *, host: str, source: str = "nginx_access") -> LogEvent | None:
    line = line.rstrip("\r\n")
    m = _COMBINED.match(line)
    if m is None:
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    status = int(m["status"])
    fields: dict[str, object] = {
        "src_ip": m["ip"],
        "status": status,
        "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
    }
    if m["user"] != "-":
        fields["user"] = m["user"]
    if req := _REQUEST.match(m["request"]):
        fields.update(method=req["method"], path=req["path"], protocol=req["protocol"])
    else:
        fields["request"] = m["request"]
    if m["referer"] not in (None, "-"):
        fields["referer"] = m["referer"]
    if m["ua"] not in (None, "-"):
        fields["user_agent"] = m["ua"]
    if m["extra"] and (rt := _REQUEST_TIME.search(m["extra"])):
        fields["request_time"] = float(rt["rt"])

    method = fields.get("method", "-")
    path = fields.get("path", m["request"])
    return LogEvent(
        timestamp=ts,
        host=host,
        source=source,
        severity=_status_severity(status),
        category=Category.HTTP_ACCESS.value,
        message=f"{method} {path} {status}",
        fields=fields,
    )


def parse_nginx_error(
    line: str, *, host: str, source: str = "nginx_error", tz: tzinfo = UTC
) -> LogEvent | None:
    """El error log usa hora local del servidor sin offset: se aplica la zona del host."""
    line = line.rstrip("\r\n")
    m = _ERROR.match(line)
    if m is None:
        return None
    ts = datetime.strptime(m["time"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=tz)
    msg = m["msg"]
    fields: dict[str, object] = {"level": m["level"], "pid": int(m["pid"])}
    if m["cid"]:
        fields["connection_id"] = int(m["cid"])
    for kv in _ERROR_KV.finditer(msg):
        key = "src_ip" if kv["key"] == "client" else kv["key"]
        fields[key] = kv["value"]
    # El mensaje "útil" es lo anterior a ", client:" (el resto ya está en fields)
    short = msg.split(", client:", 1)[0]
    return LogEvent(
        timestamp=ts,
        host=host,
        source=source,
        severity=_ERROR_LEVELS.get(m["level"], Severity.ERROR),
        category=Category.HTTP_ERROR.value,
        message=short,
        fields=fields,
    )

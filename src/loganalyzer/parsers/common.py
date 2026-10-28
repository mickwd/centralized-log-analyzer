"""Clasificación compartida entre syslog y journald.

Ambos formatos terminan en (programa, mensaje). La categoría y los campos se
derivan del contenido, así una línea de sshd se clasifica igual venga de
/var/log/auth.log o de `journalctl -o json`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from loganalyzer.models import Category, Severity
from loganalyzer.parsers.sshd import parse_sshd_message

_UNIT_EXITED = re.compile(
    r"^(?P<service>[\w@.\-]+)\.service: Main process exited, code=(?P<code>\w+), "
    r"status=(?P<status>[^\s]+)"
)
_UNIT_FAILED = re.compile(
    r"^(?P<service>[\w@.\-]+)\.service: Failed with result '(?P<result>[^']+)'"
)
_UNIT_RESTART = re.compile(
    r"^(?P<service>[\w@.\-]+)\.service: Scheduled restart job, restart counter is at (?P<n>\d+)"
)
_OOM = re.compile(r"Out of memory: Killed process (?P<pid>\d+) \((?P<process>[^)]+)\)")
_SEGFAULT = re.compile(r"(?P<process>\S+)\[(?P<pid>\d+)\]: segfault at")

_ERROR_WORDS = re.compile(r"\b(error|failed|failure|fatal|panic|exception|denied)\b", re.I)
_WARN_WORDS = re.compile(r"\b(warn|warning|timeout|timed out|retry|degraded)\b", re.I)


@dataclass
class Classification:
    category: str
    severity: Severity
    fields: dict[str, Any] = field(default_factory=dict)


def guess_severity(message: str, default: Severity = Severity.INFO) -> Severity:
    """Heurística para formatos sin severidad explícita (RFC3164 sin PRI)."""
    if _ERROR_WORDS.search(message):
        return Severity.ERROR
    if _WARN_WORDS.search(message):
        return Severity.WARNING
    return default


def classify(app: str | None, message: str, severity: Severity | None = None) -> Classification:
    """Determina categoría, severidad y campos a partir del programa y el mensaje."""
    app_name = (app or "").lower()

    if app_name in {"sshd", "sshd-session"}:
        ssh = parse_sshd_message(message)
        if ssh is not None:
            return Classification(ssh.category, ssh.severity, ssh.fields)

    if app_name == "systemd" or app_name.startswith("systemd"):
        if m := _UNIT_EXITED.search(message):
            return Classification(
                Category.SERVICE_CRASH.value,
                Severity.ERROR,
                {"service": m["service"], "exit_code": m["code"], "exit_status": m["status"]},
            )
        if m := _UNIT_FAILED.search(message):
            # Se emite junto con "Main process exited"; lo registramos como
            # restart-related para no contar dos veces el mismo crash.
            return Classification(
                Category.SERVICE_RESTART.value,
                Severity.WARNING,
                {"service": m["service"], "result": m["result"]},
            )
        if m := _UNIT_RESTART.search(message):
            return Classification(
                Category.SERVICE_RESTART.value,
                Severity.WARNING,
                {"service": m["service"], "restart_counter": int(m["n"])},
            )

    if app_name == "kernel":
        if m := _OOM.search(message):
            return Classification(
                Category.SERVICE_CRASH.value,
                Severity.CRITICAL,
                {"service": m["process"], "pid": int(m["pid"]), "reason": "oom"},
            )
        if m := _SEGFAULT.search(message):
            return Classification(
                Category.SERVICE_CRASH.value,
                Severity.ERROR,
                {"service": m["process"], "pid": int(m["pid"]), "reason": "segfault"},
            )

    final_severity = severity if severity is not None else guess_severity(message)
    category = (
        Category.APPLICATION_ERROR.value
        if final_severity.level >= Severity.ERROR.level
        else Category.SYSTEM.value
    )
    return Classification(category, final_severity, {})

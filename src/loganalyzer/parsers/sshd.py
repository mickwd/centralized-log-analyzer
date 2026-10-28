"""Parser de mensajes de autenticación de OpenSSH (sshd)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from loganalyzer.models import Category, Severity

_FAILED_PASSWORD = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_MAX_AUTH = re.compile(
    r"^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)


@dataclass(frozen=True)
class SshdResult:
    action: str
    category: str
    severity: Severity
    fields: dict[str, Any]


def _base_fields(match: re.Match[str], action: str) -> dict[str, Any]:
    fields: dict[str, Any] = {"action": action, "user": match["user"], "src_ip": match["ip"]}
    port = match.groupdict().get("port")
    if port:
        fields["src_port"] = int(port)
    return fields


def parse_sshd_message(message: str) -> SshdResult | None:
    """Devuelve el resultado normalizado o None si el mensaje no es de autenticación."""
    if m := _FAILED_PASSWORD.match(message):
        fields = _base_fields(m, "failed_password")
        fields["method"] = m["method"]
        fields["invalid_user"] = bool(m["invalid"])
        return SshdResult("failed_password", Category.AUTH_FAILURE.value, Severity.WARNING, fields)

    if m := _INVALID_USER.match(message):
        # sshd loguea "Invalid user" y luego "Failed password for invalid user".
        # Lo dejamos como notice y no como auth_failure para no contar doble.
        fields = _base_fields(m, "invalid_user")
        fields["invalid_user"] = True
        return SshdResult("invalid_user", Category.SYSTEM.value, Severity.NOTICE, fields)

    if m := _ACCEPTED.match(message):
        fields = _base_fields(m, "accepted")
        fields["method"] = m["method"]
        return SshdResult("accepted", Category.AUTH_SUCCESS.value, Severity.INFO, fields)

    if m := _MAX_AUTH.match(message):
        # Resume intentos ya contados en las líneas "Failed ..." de la misma conexión
        fields = _base_fields(m, "max_auth_exceeded")
        return SshdResult("max_auth_exceeded", Category.SYSTEM.value, Severity.WARNING, fields)

    return None

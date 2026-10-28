"""Notificadores de incidentes. Se agregan implementando `Notifier.send`."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Any, Protocol

import httpx

from loganalyzer.config import Settings

log = logging.getLogger(__name__)


class Notifier(Protocol):
    name: str

    def send(self, incident: dict[str, Any]) -> None: ...


def format_incident(incident: dict[str, Any]) -> str:
    return (
        f"[{incident['severity'].upper()}] {incident['title']} "
        f"(regla {incident['rule_id']}, {incident['count']} eventos, "
        f"{incident['first_seen']} -> {incident['last_seen']})"
    )


class LogNotifier:
    name = "log"

    def send(self, incident: dict[str, Any]) -> None:
        log.warning("INCIDENTE %s", format_incident(incident))


class WebhookNotifier:
    """POST JSON. Incluye `text` para que funcione directo con Slack/Teams/Mattermost."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0, client: httpx.Client | None = None) -> None:
        self.url = url
        self.timeout = timeout
        self.client = client

    def send(self, incident: dict[str, Any]) -> None:
        payload = {"text": format_incident(incident), "incident": incident}
        if self.client is not None:
            response = self.client.post(self.url, json=payload, timeout=self.timeout)
        else:
            response = httpx.post(self.url, json=payload, timeout=self.timeout)
        response.raise_for_status()


class EmailNotifier:
    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        user: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        smtp_factory: Any = smtplib.SMTP,
    ) -> None:
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients = recipients
        self.user = user
        self.password = password
        self.starttls = starttls
        self.smtp_factory = smtp_factory

    def build_message(self, incident: dict[str, Any]) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = f"[loganalyzer][{incident['severity']}] {incident['title']}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        lines = [format_incident(incident), "", incident.get("description") or ""]
        for key, value in (incident.get("context") or {}).items():
            lines.append(f"{key}: {value}")
        msg.set_content("\n".join(lines))
        return msg

    def send(self, incident: dict[str, Any]) -> None:
        with self.smtp_factory(self.host, self.port, timeout=10) as smtp:
            if self.starttls:
                smtp.starttls()
            if self.user and self.password:
                smtp.login(self.user, self.password)
            smtp.send_message(self.build_message(incident))


def build_notifiers(settings: Settings) -> list[Notifier]:
    notifiers: list[Notifier] = [LogNotifier()]
    if settings.webhook_url:
        notifiers.append(WebhookNotifier(settings.webhook_url))
    if settings.smtp_host and settings.smtp_to:
        notifiers.append(
            EmailNotifier(
                settings.smtp_host,
                settings.smtp_port,
                settings.smtp_from,
                [r.strip() for r in settings.smtp_to.split(",") if r.strip()],
                settings.smtp_user,
                settings.smtp_password,
                settings.smtp_starttls,
            )
        )
    return notifiers


def dispatch(notifiers: list[Notifier], incident: dict[str, Any]) -> list[str]:
    """Envía a todos los canales. Un canal caído no frena a los demás; devuelve errores."""
    errors = []
    for notifier in notifiers:
        try:
            notifier.send(incident)
        except Exception as exc:
            log.error("notificador %s falló: %s", notifier.name, exc)
            errors.append(f"{notifier.name}: {exc}")
    return errors

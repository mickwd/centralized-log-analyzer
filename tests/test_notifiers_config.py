from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from loganalyzer.config import Settings, load_inventory
from loganalyzer.notifiers import (
    EmailNotifier,
    LogNotifier,
    WebhookNotifier,
    build_notifiers,
    format_incident,
)

INCIDENT = {
    "id": 1,
    "rule_id": "ssh_bruteforce",
    "title": "Fuerza bruta SSH desde 203.0.113.45",
    "description": "desc",
    "severity": "high",
    "count": 45,
    "first_seen": "2026-10-28T12:00:00+00:00",
    "last_seen": "2026-10-28T12:04:00+00:00",
    "context": {"users": ["root"]},
}


def test_format_incident():
    text = format_incident(INCIDENT)
    assert text.startswith("[HIGH] Fuerza bruta SSH")
    assert "45 eventos" in text


def test_webhook_posts_json():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    WebhookNotifier("https://hooks.example.com/x", client=client).send(INCIDENT)
    assert seen["url"] == "https://hooks.example.com/x"
    assert seen["body"]["incident"]["rule_id"] == "ssh_bruteforce"
    assert "Fuerza bruta" in seen["body"]["text"]


def test_webhook_raises_on_http_error():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(httpx.HTTPStatusError):
        WebhookNotifier("https://hooks.example.com/x", client=client).send(INCIDENT)


class FakeSMTP:
    instances: list[FakeSMTP] = []

    def __init__(self, host, port, timeout):
        self.host, self.port = host, port
        self.calls: list[str] = []
        self.messages = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(f"login:{user}")

    def send_message(self, msg):
        self.messages.append(msg)


def test_email_notifier():
    notifier = EmailNotifier(
        "smtp.example.com", 587, "alertas@example.com", ["noc@example.com", "l2@example.com"],
        user="alertas", password="x", smtp_factory=FakeSMTP,
    )  # fmt: skip
    notifier.send(INCIDENT)
    smtp = FakeSMTP.instances[-1]
    assert smtp.calls == ["starttls", "login:alertas"]
    msg = smtp.messages[0]
    assert msg["To"] == "noc@example.com, l2@example.com"
    assert "[high]" in msg["Subject"]
    assert "users: ['root']" in msg.get_content()


def test_build_notifiers_from_settings():
    assert [
        n.name for n in build_notifiers(Settings(_env_file=None, webhook_url=None, smtp_host=None))
    ] == ["log"]
    settings = Settings(
        webhook_url="https://hooks.example.com/x", smtp_host="smtp", smtp_to="a@x.com, b@x.com"
    )
    notifiers = build_notifiers(settings)
    assert [n.name for n in notifiers] == ["log", "webhook", "email"]
    assert notifiers[2].recipients == ["a@x.com", "b@x.com"]
    LogNotifier().send(INCIDENT)  # no explota


def test_inventory_defaults_and_validation(tmp_path):
    f = tmp_path / "hosts.yaml"
    f.write_text(
        "defaults: {initial_position: end, timezone: America/Argentina/Buenos_Aires}\n"
        "hosts:\n"
        "  - {name: a, type: local}\n"
        "  - {name: b, type: ssh, address: 10.0.0.1, timezone: UTC}\n",
        encoding="utf-8",
    )
    inv = load_inventory(f)
    assert inv.hosts[0].initial_position == "end"
    assert inv.hosts[0].timezone == "America/Argentina/Buenos_Aires"
    assert inv.hosts[1].timezone == "UTC"

    f.write_text(
        "hosts:\n  - {name: a, type: local}\n  - {name: a, type: local}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="duplicados"):
        load_inventory(f)

    f.write_text("hosts:\n  - {name: a, type: local, timezone: Mars/Base}\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_inventory(f)

    f.write_text("hosts:\n  - {name: a, type: ftp}\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_inventory(f)


def test_credentials_resolved_from_env(monkeypatch):
    from loganalyzer.config import Credentials

    monkeypatch.setenv("X_USER", "svc")
    creds = Credentials(username_env="X_USER", password_env="X_MISSING")
    assert creds.resolve() == ("svc", None, None)


def test_example_inventories_are_valid():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "config"
    assert len(load_inventory(root / "hosts.example.yaml").hosts) == 4
    assert len(load_inventory(root / "hosts.compose.yaml").hosts) == 2
    assert {h.name for h in load_inventory(root / "hosts.demo.yaml").hosts} == {
        "web-01",
        "db-01",
        "dc-01",
    }

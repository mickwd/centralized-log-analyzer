"""Pipeline completo: generador de samples -> collect -> detect, y casos de error."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loganalyzer.collectors import CollectResult
from loganalyzer.config import Inventory, Settings, load_inventory
from loganalyzer.pipeline import run_collection, run_detection
from loganalyzer.rules import load_rules
from loganalyzer.storage import repository as repo

ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_samples", ROOT / "scripts" / "generate_samples.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_samples"] = module
    spec.loader.exec_module(module)
    return module


class RecordingNotifier:
    name = "recording"

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, incident: dict) -> None:
        self.sent.append(incident)


class BrokenNotifier:
    name = "broken"

    def send(self, incident: dict) -> None:
        raise ConnectionError("smtp caído")


@pytest.fixture
def demo_inventory(tmp_path, monkeypatch) -> Inventory:
    gen = _load_generator()
    monkeypatch.setattr(sys, "argv", ["generate_samples.py", "--out", str(tmp_path / "samples")])
    gen.main()
    monkeypatch.chdir(tmp_path)  # el inventario demo usa rutas relativas samples/...
    return load_inventory(ROOT / "config" / "hosts.demo.yaml")


def test_end_to_end_demo(demo_inventory, session_factory):
    settings = Settings(database_url="sqlite://")
    reports = run_collection(demo_inventory, session_factory, settings)
    assert {r.host for r in reports} == {"web-01", "db-01", "dc-01"}
    assert all(not r.errors for r in reports)
    assert all(r.unparsed == 0 for r in reports)
    total = sum(r.events for r in reports)
    assert total > 3000

    # Segunda recolección: los offsets evitan duplicados
    again = run_collection(demo_inventory, session_factory, settings)
    assert sum(r.events for r in again) == 0

    notifier = RecordingNotifier()
    rules = load_rules(ROOT / "config" / "rules.yaml")
    since = datetime.now(UTC) - timedelta(days=10)
    report = run_detection(rules, session_factory, [notifier], since=since)
    fired = {i["rule_id"] for i in report.new_incidents}
    assert fired >= {
        "ssh_bruteforce",
        "windows_logon_bruteforce",
        "account_lockout",
        "service_crash_loop",
        "unexpected_shutdown",
        "repeated_error",
        "nginx_5xx_spike",
    }
    assert len(notifier.sent) == len(report.new_incidents)
    titles = " ".join(i["title"] for i in report.new_incidents)
    assert "203.0.113.45" in titles
    assert "app-worker" in titles and "Print Spooler" in titles

    # Re-evaluar no genera ni notifica duplicados
    report2 = run_detection(rules, session_factory, [notifier], since=since)
    assert report2.new_incidents == []
    assert len(notifier.sent) == len(report.new_incidents)


def test_failing_host_does_not_stop_others(session_factory, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Oct 28 12:00:00 a sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n",
        encoding="utf-8",
    )
    inventory = Inventory(
        hosts=[
            {"name": "broken", "type": "local", "files": []},
            {"name": "ok", "type": "local", "files": [{"path": str(log), "format": "auth"}]},
            {"name": "off", "type": "local", "enabled": False},
        ]
    )

    class Exploding:
        def collect(self, get_state) -> CollectResult:
            raise TimeoutError("ssh timeout")

    def factory(host):
        if host.name == "broken":
            return Exploding()
        from loganalyzer.collectors import build_collector

        return build_collector(host)

    reports = run_collection(inventory, session_factory, Settings(), collector_factory=factory)
    by_host = {r.host: r for r in reports}
    assert set(by_host) == {"broken", "ok"}
    assert by_host["broken"].errors == ["TimeoutError: ssh timeout"]
    assert by_host["ok"].events == 1


def test_only_hosts_filter(session_factory):
    inventory = Inventory(hosts=[{"name": "a", "type": "local"}, {"name": "b", "type": "local"}])
    reports = run_collection(inventory, session_factory, Settings(), only_hosts=["b"])
    assert [r.host for r in reports] == ["b"]


def test_notifier_failure_is_reported(session_factory, make_event):
    from loganalyzer.rules import Rule

    with session_factory() as s:
        repo.add_events(s, [make_event(0, category="account_lockout", user="x")])
        s.commit()
    rule = Rule(
        id="lock", type="match", title="t", severity="low", filter={"category": "account_lockout"}
    )
    good = RecordingNotifier()
    report = run_detection(
        [rule], session_factory, [BrokenNotifier(), good], since=datetime(2020, 1, 1, tzinfo=UTC)
    )
    assert len(report.new_incidents) == 1
    assert report.notification_errors == ["broken: smtp caído"]
    assert len(good.sent) == 1

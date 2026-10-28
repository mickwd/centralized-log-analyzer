from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from loganalyzer.api import create_app
from loganalyzer.config import Settings
from loganalyzer.models import IncidentCandidate, LogEvent, Severity
from loganalyzer.storage import repository as repo


@pytest.fixture
def client(session_factory):
    now = datetime.now(UTC).replace(microsecond=0)
    events = [
        LogEvent(
            timestamp=now - timedelta(minutes=i),
            host="web-01",
            source="auth",
            severity=Severity.WARNING,
            category="auth_failure",
            message=f"Failed password for root from 203.0.113.45 port {4000 + i} ssh2",
            fields={"src_ip": "203.0.113.45", "user": "root"},
        )
        for i in range(12)
    ]
    events += [
        LogEvent(
            timestamp=now - timedelta(minutes=5 + i),
            host="db-01",
            source="syslog",
            severity=Severity.ERROR,
            category="application_error",
            message=f'ERROR: duplicate key "orders_pkey" Key (id)=({900 + i}) already exists',
        )
        for i in range(5)
    ]
    events.append(
        LogEvent(
            timestamp=now - timedelta(days=3),
            host="db-01",
            source="syslog",
            severity=Severity.ERROR,
            category="application_error",
            message="ERROR: canceling statement due to statement timeout",
        )
    )
    with session_factory() as s:
        repo.add_events(s, events)
        repo.upsert_incidents(
            s,
            [
                IncidentCandidate(
                    rule_id="ssh_bruteforce",
                    dedup_key="ssh_bruteforce|web-01|203.0.113.45",
                    title="Fuerza bruta SSH",
                    severity="high",
                    host="web-01",
                    first_seen=now - timedelta(minutes=11),
                    last_seen=now,
                    count=12,
                )
            ],
        )
        s.commit()
    app = create_app(Settings(database_url="sqlite://"), session_factory=session_factory)
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_dashboard_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Chart.js" in response.text or "chart.umd" in response.text
    assert client.get("/static/app.js").status_code == 200


def test_meta(client):
    meta = client.get("/api/meta").json()
    assert meta["hosts"] == ["db-01", "web-01"]
    assert "auth_failure" in meta["categories"]


def test_search_filters(client):
    data = client.get("/api/events", params={"host": "web-01"}).json()
    assert data["total"] == 12
    assert data["items"][0]["timestamp"] >= data["items"][-1]["timestamp"]

    data = client.get("/api/events", params={"min_severity": "error"}).json()
    assert data["total"] == 6
    assert {i["host"] for i in data["items"]} == {"db-01"}

    data = client.get("/api/events", params={"q": "duplicate", "limit": 2}).json()
    assert data["total"] == 5 and len(data["items"]) == 2

    data = client.get("/api/events", params={"src_ip": "203.0.113.45", "category": "auth_failure"})
    assert data.json()["total"] == 12


def test_search_time_range(client):
    since = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    data = client.get("/api/events", params={"since": since, "host": "db-01"}).json()
    assert data["total"] == 5


def test_search_validation(client):
    assert client.get("/api/events", params={"limit": 5000}).status_code == 422
    assert client.get("/api/events", params={"severity": "loud"}).status_code == 422


def test_stats(client):
    summary = client.get("/api/stats/summary", params={"hours": 24}).json()
    assert summary["total_events"] == 17
    assert summary["by_host"] == {"web-01": 12, "db-01": 5}
    assert summary["open_incidents"] == 1

    per_hour = client.get("/api/stats/errors-per-hour").json()
    assert [s["host"] for s in per_hour["series"]] == ["db-01"]
    assert sum(per_hour["series"][0]["data"]) == 5

    top = client.get("/api/stats/top-signatures").json()
    assert top[0]["count"] == 5
    assert "<N>" in top[0]["template"]

    ips = client.get("/api/stats/top-ips").json()
    assert ips[0] == {
        "src_ip": "203.0.113.45",
        "auth_failures": 12,
        "http_errors": 0,
        "total": 12,
        "hosts": "web-01",
    }


def test_new_signatures(client):
    rows = client.get("/api/stats/new-signatures").json()
    templates = [r["template"] for r in rows]
    assert any("duplicate key" in t for t in templates)
    assert not any("statement timeout" in t for t in templates)


def test_incident_ack_flow(client):
    (incident,) = client.get("/api/incidents", params={"status": "open"}).json()
    response = client.post(
        f"/api/incidents/{incident['id']}/ack", json={"by": "soporte-l2", "note": "bloqueada en fw"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "acknowledged"
    assert body["acked_by"] == "soporte-l2"
    assert client.get("/api/incidents", params={"status": "open"}).json() == []
    assert client.get(f"/api/incidents/{incident['id']}").json()["ack_note"] == "bloqueada en fw"

    resolved = client.post(f"/api/incidents/{incident['id']}/resolve").json()
    assert resolved["status"] == "resolved"


def test_incident_errors(client):
    assert client.post("/api/incidents/999/ack", json={"by": "x"}).status_code == 404
    assert client.get("/api/incidents/999").status_code == 404
    assert client.post("/api/incidents/1/ack", json={"by": ""}).status_code == 422
    assert client.get("/api/incidents", params={"status": "weird"}).status_code == 422

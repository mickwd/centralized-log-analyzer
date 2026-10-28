from __future__ import annotations

from datetime import timedelta

import pandas as pd

from loganalyzer import analytics
from loganalyzer.models import Severity
from loganalyzer.storage import repository as repo
from tests.conftest import NOW


def _df(session_factory, events) -> pd.DataFrame:
    with session_factory() as s:
        repo.add_events(s, events)
        s.commit()
        return repo.events_dataframe(s)


def test_top_errors_groups_by_signature(session_factory, make_event):
    events = [
        make_event(i, host="db-01", severity=Severity.ERROR, message=f"timeout after {i} ms")
        for i in range(5)
    ]
    events += [
        make_event(i, host="web-01", severity=Severity.ERROR, message="disk full") for i in range(2)
    ]
    events += [make_event(i, severity=Severity.INFO, message="ok") for i in range(10)]
    top = analytics.top_errors(_df(session_factory, events))
    assert list(top["count"]) == [5, 2]
    assert top.iloc[0]["template"] == "timeout after <N> ms"
    assert top.iloc[0]["hosts"] == "db-01"


def test_top_errors_excludes_access_log_requests(session_factory, make_event):
    events = [
        make_event(
            i, severity=Severity.ERROR, category="http_access", message="GET / 502", status=502
        )
        for i in range(5)
    ]
    assert analytics.top_errors(_df(session_factory, events)).empty


def test_top_offending_ips(session_factory, make_event):
    events = [make_event(i, category="auth_failure", src_ip="1.1.1.1") for i in range(4)]
    events += [
        make_event(i, category="http_access", source="nginx_access", src_ip="2.2.2.2", status=404)
        for i in range(2)
    ]
    events += [
        make_event(i, category="http_access", src_ip="3.3.3.3", status=200) for i in range(9)
    ]
    events += [make_event(0, category="auth_failure", src_ip="2.2.2.2")]
    top = analytics.top_offending_ips(_df(session_factory, events))
    assert top.to_dict(orient="records") == [
        {"src_ip": "1.1.1.1", "auth_failures": 4, "http_errors": 0, "total": 4, "hosts": "web-01"},
        {"src_ip": "2.2.2.2", "auth_failures": 1, "http_errors": 2, "total": 3, "hosts": "web-01"},
    ]


def test_errors_per_host_per_hour_fills_gaps(session_factory, make_event):
    events = [
        make_event(0, host="a", severity=Severity.ERROR),
        make_event(60, host="a", severity=Severity.ERROR),
        make_event(3 * 3600, host="b", severity=Severity.CRITICAL),
    ]
    pivot = analytics.errors_per_host_per_hour(_df(session_factory, events))
    assert list(pivot.columns) == ["a", "b"]
    assert len(pivot) == 4  # 4 horas consecutivas, con huecos en 0
    assert pivot["a"].tolist() == [2, 0, 0, 0]
    assert pivot["b"].tolist() == [0, 0, 0, 1]


def test_new_signatures(session_factory, make_event):
    old = NOW - timedelta(days=3)
    events = [
        make_event(0, base=old, severity=Severity.ERROR, message="known error 1"),
        make_event(0, severity=Severity.ERROR, message="known error 2"),
        make_event(10, severity=Severity.ERROR, message="brand new failure id 77"),
        make_event(20, severity=Severity.ERROR, message="brand new failure id 78"),
        # visto hace 10 días: fuera del baseline de 7 días, cuenta como nuevo
        make_event(0, base=NOW - timedelta(days=10), severity=Severity.ERROR, message="ancient"),
        make_event(30, severity=Severity.ERROR, message="ancient"),
    ]
    result = analytics.new_signatures(_df(session_factory, events), now=NOW + timedelta(minutes=1))
    assert dict(zip(result["template"], result["count"], strict=True)) == {
        "brand new failure id <N>": 2,
        "ancient": 1,
    }


def test_empty_dataframe_is_safe(session_factory):
    df = _df(session_factory, [])
    assert analytics.top_errors(df).empty
    assert analytics.top_offending_ips(df).empty
    assert analytics.errors_per_host_per_hour(df).empty
    assert analytics.new_signatures(df).empty
    assert analytics.severity_breakdown(df) == {}

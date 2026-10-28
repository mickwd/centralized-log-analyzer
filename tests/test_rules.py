from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from loganalyzer.models import Category, IncidentSeverity, Severity
from loganalyzer.rules import Rule, evaluate, find_episodes, load_rules, parse_duration
from loganalyzer.storage import repository as repo
from tests.conftest import NOW

ROOT = Path(__file__).resolve().parents[1]


def ts(*seconds: float):
    return [NOW + timedelta(seconds=s) for s in seconds]


def brute_force_rule(**overrides) -> Rule:
    data = {
        "id": "ssh_bruteforce",
        "type": "threshold",
        "title": "Fuerza bruta desde {fields.src_ip} en {host} ({count} en {window})",
        "severity": "high",
        "filter": {"category": "auth_failure"},
        "group_by": ["host", "fields.src_ip"],
        "window": "5m",
        "min_count": 11,
    }
    data.update(overrides)
    return Rule(**data)


def failures(make_event, n: int, every_s: float, ip: str = "203.0.113.45", start: float = 0):
    return [
        make_event(start + i * every_s, category="auth_failure", src_ip=ip, user="root")
        for i in range(n)
    ]


class TestFindEpisodes:
    def test_below_threshold(self):
        assert find_episodes(ts(0, 10, 20), timedelta(minutes=5), 4) == []

    def test_exact_threshold(self):
        eps = find_episodes(ts(0, 10, 20, 30), timedelta(minutes=5), 4)
        assert len(eps) == 1
        assert eps[0].count == 4 and eps[0].start == NOW

    def test_events_spread_outside_window(self):
        # 4 eventos pero separados 2 minutos: en 5 minutos nunca hay más de 3
        assert find_episodes(ts(0, 120, 240, 360), timedelta(minutes=5), 4) == []

    def test_overlapping_windows_merge_into_one_episode(self):
        eps = find_episodes(ts(*range(0, 600, 10)), timedelta(minutes=5), 5)
        assert len(eps) == 1
        assert eps[0].count == 60
        assert eps[0].peak == 31  # 0..300 inclusive

    def test_two_separate_bursts(self):
        first = list(range(0, 50, 5))
        second = list(range(3600, 3650, 5))
        eps = find_episodes(ts(*first, *second), timedelta(minutes=5), 10)
        assert [e.count for e in eps] == [10, 10]
        assert eps[1].start == NOW + timedelta(seconds=3600)

    def test_window_boundary_is_inclusive(self):
        assert len(find_episodes(ts(0, 300), timedelta(minutes=5), 2)) == 1
        assert find_episodes(ts(0, 301), timedelta(minutes=5), 2) == []


class TestThreshold:
    def test_more_than_10_in_5_minutes(self, make_event):
        candidates = evaluate([brute_force_rule()], failures(make_event, 11, 20))
        assert len(candidates) == 1
        c = candidates[0]
        assert c.count == 11
        assert c.severity is IncidentSeverity.HIGH
        assert c.dedup_key == "ssh_bruteforce|web-01|203.0.113.45"
        assert c.title == "Fuerza bruta desde 203.0.113.45 en web-01 (11 en 5m)"
        assert c.host == "web-01"
        assert c.context["users"] == ["root"]

    def test_exactly_10_does_not_fire(self, make_event):
        assert evaluate([brute_force_rule()], failures(make_event, 10, 20)) == []

    def test_slow_attack_does_not_fire(self, make_event):
        # 20 intentos pero uno por minuto: 6 por ventana como máximo
        assert evaluate([brute_force_rule()], failures(make_event, 20, 60)) == []

    def test_groups_are_independent(self, make_event):
        events = failures(make_event, 6, 10, ip="1.1.1.1") + failures(
            make_event, 6, 10, ip="2.2.2.2"
        )
        assert evaluate([brute_force_rule()], events) == []
        events += failures(make_event, 6, 10, ip="1.1.1.1", start=1)
        result = evaluate([brute_force_rule()], events)
        assert [c.context["group"]["fields.src_ip"] for c in result] == ["1.1.1.1"]

    def test_events_without_group_value_are_skipped(self, make_event):
        events = [make_event(i, category="auth_failure") for i in range(20)]  # sin src_ip
        assert evaluate([brute_force_rule()], events) == []

    def test_filter_by_category(self, make_event):
        events = [make_event(i, category="auth_success", src_ip="1.1.1.1") for i in range(20)]
        assert evaluate([brute_force_rule()], events) == []

    def test_unordered_input(self, make_event):
        events = list(reversed(failures(make_event, 11, 20)))
        assert len(evaluate([brute_force_rule()], events)) == 1


class TestOtherRuleTypes:
    def test_repeated_signature_groups_by_normalized_message(self, make_event):
        rule = Rule(
            id="repeated_error",
            type="repeated_signature",
            title="{count}x {template}",
            severity="medium",
            filter={"min_severity": "error"},
            group_by=["host"],
            window="15m",
            min_count=5,
        )
        events = [
            make_event(
                i * 30,
                severity=Severity.ERROR,
                category="application_error",
                message=f'duplicate key "orders_pkey" Key (id)=({1000 + i}) already exists',
            )
            for i in range(6)
        ]
        events += [
            make_event(i, severity=Severity.ERROR, message=f"disk {i} full") for i in range(3)
        ]
        events += [make_event(i, severity=Severity.WARNING, message="warn 1") for i in range(10)]
        result = evaluate([rule], events)
        assert len(result) == 1
        assert result[0].count == 6
        assert result[0].title == '6x duplicate key "orders_pkey" Key (id)=(<N>) already exists'

    def test_match_rule_one_event(self, make_event):
        rule = Rule(
            id="account_lockout",
            type="match",
            title="Cuenta bloqueada {fields.user}",
            severity="medium",
            filter={"category": "account_lockout"},
            group_by=["host", "fields.user"],
        )
        events = [
            make_event(0, category=Category.ACCOUNT_LOCKOUT, user="jperez"),
            make_event(5, category=Category.ACCOUNT_LOCKOUT, user="mgarcia"),
        ]
        titles = sorted(c.title for c in evaluate([rule], events))
        assert titles == ["Cuenta bloqueada jperez", "Cuenta bloqueada mgarcia"]

    def _ratio_rule(self) -> Rule:
        return Rule(
            id="nginx_5xx_spike",
            type="ratio",
            title="5xx {ratio}",
            severity="high",
            filter={"category": "http_access", "field_gte": {"status": 500}},
            denominator={"category": "http_access"},
            group_by=["host"],
            window="5m",
            min_count=10,
            min_ratio=0.2,
        )

    def test_ratio_fires_on_spike(self, make_event):
        events = [
            make_event(
                i, category="http_access", source="nginx_access", status=502 if i % 2 else 200
            )
            for i in range(40)
        ]
        result = evaluate([self._ratio_rule()], events)
        assert len(result) == 1
        assert result[0].context["ratio"] == pytest.approx(0.5, abs=0.05)
        assert result[0].title == "5xx 51%"

    def test_ratio_ignores_errors_under_heavy_traffic(self, make_event):
        events = [
            make_event(i * 0.1, category="http_access", status=500 if i % 20 == 0 else 200)
            for i in range(600)
        ]
        assert evaluate([self._ratio_rule()], events) == []

    def test_field_matchers_and_regex(self, make_event):
        rule = Rule(
            id="r",
            type="match",
            title="x",
            severity="low",
            filter={"fields": {"service": ["nginx", "php-fpm"]}, "message_regex": "exited"},
        )
        events = [
            make_event(0, service="nginx", message="Main process exited"),
            make_event(1, service="cron", message="Main process exited"),
            make_event(2, service="nginx", message="Started"),
        ]
        assert [c.count for c in evaluate([rule], events)] == [1]


class TestDedup:
    def test_rerun_is_idempotent(self, make_event, session_factory):
        events = failures(make_event, 15, 10)
        with session_factory() as s:
            created = repo.upsert_incidents(s, evaluate([brute_force_rule()], events))
            s.commit()
            assert len(created) == 1
            again = repo.upsert_incidents(s, evaluate([brute_force_rule()], events))
            s.commit()
            assert again == []
            rows = repo.list_incidents(s)
            assert len(rows) == 1 and rows[0].count == 15 and rows[0].occurrences == 1

    def test_continuing_attack_updates_existing(self, make_event, session_factory):
        with session_factory() as s:
            repo.upsert_incidents(s, evaluate([brute_force_rule()], failures(make_event, 12, 10)))
            later = failures(make_event, 12, 10, start=900)  # 15 min después, dentro del cooldown
            assert repo.upsert_incidents(s, evaluate([brute_force_rule()], later)) == []
            s.commit()
            (row,) = repo.list_incidents(s)
            assert row.occurrences == 2
            assert row.last_seen == later[-1].timestamp

    def test_new_incident_after_cooldown(self, make_event, session_factory):
        rule = brute_force_rule(cooldown="30m")
        with session_factory() as s:
            repo.upsert_incidents(s, evaluate([rule], failures(make_event, 12, 10)))
            later = failures(make_event, 12, 10, start=3 * 3600)
            assert len(repo.upsert_incidents(s, evaluate([rule], later))) == 1

    def test_resolved_incident_is_not_reused(self, make_event, session_factory):
        with session_factory() as s:
            (row,) = repo.upsert_incidents(
                s, evaluate([brute_force_rule()], failures(make_event, 12, 5))
            )
            repo.set_incident_status(s, row.id, "resolved")
            later = failures(make_event, 12, 5, start=600)
            assert len(repo.upsert_incidents(s, evaluate([brute_force_rule()], later))) == 1

    def test_same_evaluation_two_bursts_within_cooldown_collapse(self, make_event, session_factory):
        events = failures(make_event, 12, 5) + failures(make_event, 12, 5, start=1200)
        candidates = evaluate([brute_force_rule()], events)
        assert len(candidates) == 2
        with session_factory() as s:
            assert len(repo.upsert_incidents(s, candidates)) == 1


class TestLoader:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("30s", timedelta(seconds=30)),
            ("5m", timedelta(minutes=5)),
            ("2h", timedelta(hours=2)),
            ("1d", timedelta(days=1)),
            (15, timedelta(minutes=15)),
        ],
    )
    def test_durations(self, value, expected):
        assert parse_duration(value) == expected

    def test_bad_duration(self):
        with pytest.raises(ValueError):
            parse_duration("5 minutes")

    def test_ratio_requires_denominator(self):
        with pytest.raises(ValidationError, match="denominator"):
            Rule(id="x", type="ratio", title="t", severity="low", min_ratio=0.1)

    def test_unknown_type(self):
        with pytest.raises(ValidationError):
            Rule(id="x", type="anomaly", title="t", severity="low")

    def test_project_rules_file_is_valid(self):
        rules = load_rules(ROOT / "config" / "rules.yaml")
        ids = {r.id for r in rules}
        assert {"ssh_bruteforce", "service_crash_loop", "nginx_5xx_spike", "account_lockout"} <= ids

    def test_disabled_rules_and_duplicate_ids(self, tmp_path):
        f = tmp_path / "r.yaml"
        f.write_text(
            "rules:\n"
            "  - {id: a, type: match, title: t, severity: low, enabled: false}\n"
            "  - {id: b, type: match, title: t, severity: low}\n",
            encoding="utf-8",
        )
        assert [r.id for r in load_rules(f)] == ["b"]
        f.write_text(
            "rules:\n"
            "  - {id: a, type: match, title: t, severity: low}\n"
            "  - {id: a, type: match, title: t, severity: low}\n",
            encoding="utf-8",
        )
        with pytest.raises(ValidationError, match="repetidos"):
            load_rules(f)

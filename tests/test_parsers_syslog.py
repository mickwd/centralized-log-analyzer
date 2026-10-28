from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from loganalyzer.models import Category, Severity
from loganalyzer.parsers.syslog import parse_rfc3164, parse_rfc5424, parse_syslog_line

NOW = datetime(2026, 10, 28, 15, 0, tzinfo=UTC)
ART = ZoneInfo("America/Argentina/Buenos_Aires")


class TestRfc3164:
    def test_basic_line(self):
        rec = parse_rfc3164(
            "Oct 28 11:58:01 web-01 CRON[2231]: (root) CMD (run-parts /etc/cron.hourly)", now=NOW
        )
        assert rec is not None
        assert rec.timestamp == datetime(2026, 10, 28, 11, 58, 1, tzinfo=UTC)
        assert rec.hostname == "web-01"
        assert rec.app == "CRON"
        assert rec.pid == "2231"
        assert rec.message == "(root) CMD (run-parts /etc/cron.hourly)"

    def test_space_padded_day_and_pri(self):
        rec = parse_rfc3164("<38>Nov  3 07:00:00 fw-01 kernel: [UFW BLOCK] IN=eth0", now=NOW)
        assert rec is not None
        assert rec.timestamp.day == 3
        assert rec.facility == 4 and rec.severity_code == 6
        assert rec.pid is None

    def test_year_rollover_uses_previous_year(self):
        jan = datetime(2027, 1, 1, 0, 5, tzinfo=UTC)
        rec = parse_rfc3164("Dec 31 23:59:58 web-01 sshd[1]: test", now=jan)
        assert rec is not None
        assert rec.timestamp.year == 2026

    def test_local_timezone_converted_to_utc(self):
        event = parse_syslog_line("Oct 28 09:00:00 web-01 app[1]: hola", tz=ART, now=NOW)
        assert event is not None
        assert event.timestamp == datetime(2026, 10, 28, 12, 0, tzinfo=UTC)

    def test_rsyslog_iso_timestamp_variant(self):
        rec = parse_rfc3164(
            "2026-10-28T09:15:02.123456-03:00 web-01 systemd[1]: Started session 4.", now=NOW
        )
        assert rec is not None
        assert rec.timestamp.astimezone(UTC).hour == 12

    @pytest.mark.parametrize("line", ["", "garbage without format", "Foo 99 12:00:00 x y: z"])
    def test_invalid_lines(self, line):
        assert parse_syslog_line(line, now=NOW) is None


class TestRfc5424:
    def test_full_line_with_structured_data(self):
        line = (
            "<165>1 2026-10-28T12:00:00.003Z db-01 postgres 2345 ID47 "
            '[exampleSDID@32473 iut="3" eventSource="App\\]lication"][meta seq="7"] '
            "﻿ERROR: something broke"
        )
        rec = parse_rfc5424(line)
        assert rec is not None
        assert rec.facility == 20 and rec.severity_code == 5
        assert rec.app == "postgres" and rec.pid == "2345" and rec.msgid == "ID47"
        assert rec.structured_data["exampleSDID@32473"]["eventSource"] == "App]lication"
        assert rec.structured_data["meta"] == {"seq": "7"}
        assert rec.message == "ERROR: something broke"

    def test_nil_values(self):
        rec = parse_rfc5424("<34>1 2026-10-28T12:00:00+02:00 host - - - - plain message")
        assert rec is not None
        assert rec.app is None and rec.pid is None and rec.msgid is None
        assert rec.structured_data == {}
        assert rec.message == "plain message"
        assert rec.timestamp.astimezone(UTC).hour == 10

    def test_explicit_severity_wins_over_heuristic(self):
        event = parse_syslog_line(
            "<134>1 2026-10-28T12:00:00Z db-01 postgres 1 - - LOG: error count reset"
        )
        assert event is not None
        assert event.severity is Severity.INFO
        assert event.host == "db-01"

    def test_error_priority_maps_to_application_error(self):
        event = parse_syslog_line(
            '<131>1 2026-10-28T12:00:00Z db-01 postgres 1 - - ERROR:  duplicate key "orders_pkey"'
        )
        assert event is not None
        assert event.severity is Severity.ERROR
        assert event.category == Category.APPLICATION_ERROR


class TestClassification:
    def test_systemd_crash(self):
        event = parse_syslog_line(
            "Oct 28 12:00:01 web-01 systemd[1]: app-worker.service: Main process exited, "
            "code=exited, status=1/FAILURE",
            now=NOW,
        )
        assert event.category == Category.SERVICE_CRASH
        assert event.fields["service"] == "app-worker"
        assert event.fields["exit_status"] == "1/FAILURE"

    def test_systemd_restart_counter(self):
        event = parse_syslog_line(
            "Oct 28 12:00:06 web-01 systemd[1]: nginx.service: Scheduled restart job, "
            "restart counter is at 5.",
            now=NOW,
        )
        assert event.category == Category.SERVICE_RESTART
        assert event.fields["restart_counter"] == 5

    def test_kernel_oom(self):
        event = parse_syslog_line(
            "Oct 28 12:00:00 db-01 kernel: Out of memory: Killed process 4242 (java) "
            "total-vm:8123456kB",
            now=NOW,
        )
        assert event.category == Category.SERVICE_CRASH
        assert event.severity is Severity.CRITICAL
        assert event.fields["service"] == "java"

    def test_sshd_through_syslog_gets_auth_fields(self):
        event = parse_syslog_line(
            "Oct 28 12:00:00 web-01 sshd[999]: Failed password for root from 203.0.113.9 "
            "port 51515 ssh2",
            source="auth",
            now=NOW,
        )
        assert event.category == Category.AUTH_FAILURE
        assert event.fields["src_ip"] == "203.0.113.9"
        assert event.source == "auth"

    def test_keyword_severity_heuristic(self):
        event = parse_syslog_line("Oct 28 12:00:00 h app[1]: request timed out", now=NOW)
        assert event.severity is Severity.WARNING

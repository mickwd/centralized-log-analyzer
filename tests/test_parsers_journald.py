import json
from datetime import UTC, datetime

from loganalyzer.models import Category, Severity
from loganalyzer.parsers.journald import parse_journald_json

BASE = {
    "__CURSOR": "s=7d1c;i=1a2b01;b=3f2a;m=1a2b;t=65ed942afde00",
    "__REALTIME_TIMESTAMP": "1793188800000000",  # 2026-10-28T12:00:00Z
    "_HOSTNAME": "db-01",
    "SYSLOG_IDENTIFIER": "sshd",
    "_SYSTEMD_UNIT": "ssh.service",
    "PRIORITY": "6",
    "_PID": "1234",
    "MESSAGE": "Accepted publickey for dba from 10.10.0.5 port 50000 ssh2",
}


def test_sshd_entry():
    event = parse_journald_json(json.dumps(BASE))
    assert event is not None
    assert event.timestamp == datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    assert event.host == "db-01"
    assert event.source == "journald"
    assert event.category == Category.AUTH_SUCCESS
    assert event.fields["user"] == "dba"
    assert event.fields["cursor"] == BASE["__CURSOR"]
    assert event.fields["unit"] == "ssh.service"


def test_host_override_and_dict_input():
    event = parse_journald_json(BASE, host="db-01.prod")
    assert event.host == "db-01.prod"


def test_priority_mapping():
    entry = {**BASE, "SYSLOG_IDENTIFIER": "postgres", "PRIORITY": "3", "MESSAGE": "FATAL: x"}
    event = parse_journald_json(entry)
    assert event.severity is Severity.ERROR
    assert event.category == Category.APPLICATION_ERROR


def test_binary_message_as_byte_list():
    entry = {**BASE, "SYSLOG_IDENTIFIER": "app", "MESSAGE": [104, 111, 108, 97, 0xFF]}
    event = parse_journald_json(entry)
    assert event.message.startswith("hola")


def test_systemd_crash_via_journald():
    entry = {
        **BASE,
        "SYSLOG_IDENTIFIER": "systemd",
        "PRIORITY": "4",
        "MESSAGE": "nginx.service: Main process exited, code=killed, status=9/KILL",
    }
    event = parse_journald_json(entry)
    assert event.category == Category.SERVICE_CRASH
    assert event.fields["service"] == "nginx"


def test_invalid_inputs():
    assert parse_journald_json("") is None
    assert parse_journald_json("{not json") is None
    assert parse_journald_json('{"MESSAGE": "no timestamp"}') is None
    assert parse_journald_json("[1, 2]") is None

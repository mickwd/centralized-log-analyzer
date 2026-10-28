import json
from datetime import UTC, datetime

import pytest

from loganalyzer.models import Category, Severity
from loganalyzer.parsers.windows import parse_windows_event, parse_windows_timestamp

SEC = "Microsoft-Windows-Security-Auditing"


def raw(event_id, log, level=0, provider=SEC, data=None, **extra):
    return {
        "RecordId": 884201,
        "Id": event_id,
        "LogName": log,
        "ProviderName": provider,
        "Level": level,
        "TimeCreated": "2026-10-28T12:00:00.1234567Z",
        "MachineName": "DC-01.corp.example",
        "Message": "Some long message.\r\nSecond line",
        "Data": data or {},
        **extra,
    }


def test_failed_logon_4625():
    event = parse_windows_event(
        raw(
            4625,
            "Security",
            data={
                "TargetUserName": "jperez",
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": "198.51.100.23",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "WorkstationName": "KALI",
            },
        )
    )
    assert event.category == Category.AUTH_FAILURE
    assert event.severity is Severity.WARNING
    assert event.host == "dc-01"
    assert event.source == "windows_security"
    assert event.fields["user"] == "jperez"
    assert event.fields["src_ip"] == "198.51.100.23"
    assert event.fields["logon_type"] == "network"
    assert event.fields["sub_status"] == "0xc000006a"
    assert event.fields["record_id"] == 884201
    assert event.message == "Failed logon for jperez from 198.51.100.23"


def test_local_logon_without_ip_has_no_src_ip():
    event = parse_windows_event(
        raw(4625, "Security", data={"TargetUserName": "x", "IpAddress": "-"})
    )
    assert "src_ip" not in event.fields
    assert event.message.endswith("from local")


def test_success_logon_4624():
    event = parse_windows_event(
        raw(4624, "Security", data={"TargetUserName": "mgarcia", "LogonType": "10"})
    )
    assert event.category == Category.AUTH_SUCCESS
    assert event.fields["logon_type"] == "remote_interactive"


def test_lockout_4740():
    event = parse_windows_event(
        raw(4740, "Security", data={"TargetUserName": "jperez", "TargetDomainName": "PC-131"})
    )
    assert event.category == Category.ACCOUNT_LOCKOUT
    assert event.fields == {
        "user": "jperez",
        "caller_computer": "PC-131",
        "event_id": 4740,
        "log_name": "Security",
        "provider": SEC,
        "record_id": 884201,
    }


@pytest.mark.parametrize("event_id", [7031, 7034])
def test_service_crash(event_id):
    event = parse_windows_event(
        raw(
            event_id,
            "System",
            2,
            "Service Control Manager",
            {"param1": "Print Spooler", "param2": "3"},
        )
    )
    assert event.category == Category.SERVICE_CRASH
    assert event.fields["service"] == "Print Spooler"
    assert event.fields["crash_count"] == 3


def test_unexpected_shutdown_6008():
    event = parse_windows_event(
        raw(6008, "System", 2, "EventLog", {"param1": "03:12:44", "param2": "28/10/2026"})
    )
    assert event.category == Category.UNEXPECTED_SHUTDOWN
    assert event.severity is Severity.CRITICAL
    assert event.fields["previous_shutdown"] == "28/10/2026 03:12:44"


def test_application_error_uses_first_message_line():
    event = parse_windows_event(
        raw(
            1000,
            "Application",
            2,
            "Application Error",
            {"param1": "w3wp.exe", "param7": "0xc0000005"},
        )
    )
    assert event.category == Category.APPLICATION_ERROR
    assert event.severity is Severity.ERROR
    assert event.message == "Some long message."
    assert event.fields["faulting_app"] == "w3wp.exe"


def test_application_warning_is_system():
    event = parse_windows_event(raw(1, "Application", 3, "MsiInstaller"))
    assert event.category == Category.SYSTEM
    assert event.severity is Severity.WARNING


def test_json_string_input():
    event = parse_windows_event(json.dumps(raw(4624, "Security")))
    assert event is not None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-28T12:00:00.1234567Z", datetime(2026, 10, 28, 12, 0, 0, 123456, tzinfo=UTC)),
        ("/Date(1793188800000)/", datetime(2026, 10, 28, 12, 0, tzinfo=UTC)),
        ("2026-10-28T09:00:00-03:00", datetime(2026, 10, 28, 12, 0, tzinfo=UTC)),
    ],
)
def test_timestamp_formats(value, expected):
    assert parse_windows_timestamp(value) == expected


@pytest.mark.parametrize("value", ["", "nope", "{}", '{"Id": 1}', "[]"])
def test_invalid(value):
    assert parse_windows_event(value) is None

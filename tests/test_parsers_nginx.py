from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from loganalyzer.models import Category, Severity
from loganalyzer.parsers.nginx import parse_nginx_access, parse_nginx_error

COMBINED = (
    '181.27.91.200 - - [28/Oct/2026:09:15:02 -0300] "GET /api/cart?id=5 HTTP/1.1" 200 1532 '
    '"https://shop.example.com/" "Mozilla/5.0 (X11; Linux x86_64)"'
)


class TestAccess:
    def test_combined_line(self):
        event = parse_nginx_access(COMBINED, host="web-01")
        assert event is not None
        assert event.timestamp == datetime(2026, 10, 28, 12, 15, 2, tzinfo=UTC)
        assert event.category == Category.HTTP_ACCESS
        assert event.severity is Severity.INFO
        assert event.fields["src_ip"] == "181.27.91.200"
        assert event.fields["method"] == "GET"
        assert event.fields["path"] == "/api/cart?id=5"
        assert event.fields["status"] == 200
        assert event.fields["bytes"] == 1532
        assert event.fields["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64)"
        assert event.message == "GET /api/cart?id=5 200"

    @pytest.mark.parametrize(
        ("status", "severity"),
        [(200, Severity.INFO), (304, Severity.INFO), (404, Severity.NOTICE), (502, Severity.ERROR)],
    )
    def test_status_severity(self, status, severity):
        line = COMBINED.replace(" 200 1532 ", f" {status} 1532 ")
        assert parse_nginx_access(line, host="h").severity is severity

    def test_extra_fields_request_time_and_dash_bytes(self):
        line = (
            '2001:db8::1 - alice [28/Oct/2026:12:00:00 +0000] "POST /login HTTP/2.0" 504 - '
            '"-" "curl/8.5.0" rt=60.001 uct="0.001"'
        )
        event = parse_nginx_access(line, host="h")
        assert event.fields["src_ip"] == "2001:db8::1"
        assert event.fields["user"] == "alice"
        assert event.fields["bytes"] == 0
        assert event.fields["request_time"] == pytest.approx(60.001)
        assert "referer" not in event.fields

    def test_escaped_quotes_in_user_agent(self):
        line = (
            '1.2.3.4 - - [28/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" '
            '"Bot \\"evil\\" 1.0"'
        )
        event = parse_nginx_access(line, host="h")
        assert event is not None
        assert "evil" in event.fields["user_agent"]

    def test_malformed_request_line_kept_raw(self):
        line = '1.2.3.4 - - [28/Oct/2026:12:00:00 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"'
        event = parse_nginx_access(line, host="h")
        assert event is not None
        assert event.fields["status"] == 400
        assert "request" in event.fields

    @pytest.mark.parametrize("line", ["", "not a log line", '1.2.3.4 - - [bad date] "GET /" 200 1'])
    def test_invalid(self, line):
        assert parse_nginx_access(line, host="h") is None


class TestError:
    LINE = (
        "2026/10/28 09:15:02 [error] 1187#1187: *100042 connect() failed (111: Connection "
        "refused) while connecting to upstream, client: 181.27.91.200, server: shop.example.com, "
        'request: "GET /api/cart HTTP/1.1", upstream: "http://127.0.0.1:8080/api/cart", '
        'host: "shop.example.com"'
    )

    def test_error_line_with_context(self):
        event = parse_nginx_error(
            self.LINE, host="web-01", tz=ZoneInfo("America/Argentina/Buenos_Aires")
        )
        assert event is not None
        assert event.timestamp == datetime(2026, 10, 28, 12, 15, 2, tzinfo=UTC)
        assert event.severity is Severity.ERROR
        assert event.category == Category.HTTP_ERROR
        assert event.message == (
            "connect() failed (111: Connection refused) while connecting to upstream"
        )
        assert event.fields["src_ip"] == "181.27.91.200"
        assert event.fields["upstream"] == "http://127.0.0.1:8080/api/cart"
        assert event.fields["request"] == "GET /api/cart HTTP/1.1"
        assert event.fields["connection_id"] == 100042

    @pytest.mark.parametrize(
        ("level", "severity"),
        [("warn", Severity.WARNING), ("crit", Severity.CRITICAL), ("emerg", Severity.CRITICAL)],
    )
    def test_levels(self, level, severity):
        line = f"2026/10/28 09:15:02 [{level}] 1#1: something happened"
        event = parse_nginx_error(line, host="h")
        assert event.severity is severity
        assert "connection_id" not in event.fields

    def test_invalid(self):
        assert parse_nginx_error("nginx: [emerg] bad config", host="h") is None

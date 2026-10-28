import pytest

from loganalyzer.models import Category
from loganalyzer.parsers.sshd import parse_sshd_message


@pytest.mark.parametrize(
    ("message", "action", "category", "user", "ip", "port"),
    [
        (
            "Failed password for root from 203.0.113.45 port 52344 ssh2",
            "failed_password",
            Category.AUTH_FAILURE,
            "root",
            "203.0.113.45",
            52344,
        ),
        (
            "Failed password for invalid user oracle from 203.0.113.45 port 40022 ssh2",
            "failed_password",
            Category.AUTH_FAILURE,
            "oracle",
            "203.0.113.45",
            40022,
        ),
        (
            "Invalid user admin from 198.51.100.4 port 33210",
            "invalid_user",
            Category.SYSTEM,
            "admin",
            "198.51.100.4",
            33210,
        ),
        (
            "Accepted publickey for deploy from 10.10.0.5 port 50122 ssh2: ED25519 SHA256:abc",
            "accepted",
            Category.AUTH_SUCCESS,
            "deploy",
            "10.10.0.5",
            50122,
        ),
        (
            "Accepted password for jgomez from 2001:db8::25 port 61000 ssh2",
            "accepted",
            Category.AUTH_SUCCESS,
            "jgomez",
            "2001:db8::25",
            61000,
        ),
        (
            "error: maximum authentication attempts exceeded for root from 203.0.113.45 "
            "port 51122 ssh2 [preauth]",
            "max_auth_exceeded",
            Category.SYSTEM,
            "root",
            "203.0.113.45",
            51122,
        ),
    ],
)
def test_sshd_messages(message, action, category, user, ip, port):
    result = parse_sshd_message(message)
    assert result is not None
    assert result.action == action
    assert result.category == category
    assert result.fields["user"] == user
    assert result.fields["src_ip"] == ip
    assert result.fields["src_port"] == port


def test_invalid_user_flag():
    result = parse_sshd_message("Failed password for invalid user test from 1.2.3.4 port 1 ssh2")
    assert result.fields["invalid_user"] is True
    result = parse_sshd_message("Failed password for root from 1.2.3.4 port 1 ssh2")
    assert result.fields["invalid_user"] is False


def test_invalid_user_with_empty_name():
    result = parse_sshd_message("Invalid user  from 192.0.2.1 port 4000")
    assert result is not None
    assert result.fields["user"] == ""


@pytest.mark.parametrize(
    "message",
    [
        "Connection closed by 10.0.0.1 port 22 [preauth]",
        "Received disconnect from 10.0.0.1 port 5000:11: Bye Bye [preauth]",
        "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        "Server listening on 0.0.0.0 port 22.",
    ],
)
def test_non_auth_messages_return_none(message):
    assert parse_sshd_message(message) is None

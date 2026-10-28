import pytest

from loganalyzer.signatures import normalize_message, signature_of


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Connection to 10.0.0.5:5432 timed out", "Connection to <IP> timed out"),
        ("user id 12345 not found", "user id <N> not found"),
        ("request 7f3a9c21e0 failed", "request <HEX> failed"),
        ("pointer 0xDEADBEEF invalid", "pointer <HEX> invalid"),
        (
            "job 3fa85f64-5717-4562-b3fc-2c963f66afa6 crashed",
            "job <UUID> crashed",
        ),
        ("at 2026-10-28T12:00:01.123Z retry", "at <TS> retry"),
        ("mail to soporte@example.com bounced", "mail to <EMAIL> bounced"),
        ("GET /api/orders/88231/items", "GET /api/orders/<N>/items"),
        ("from 2001:db8::1 denied", "from <IP> denied"),
        ("too   many    spaces", "too many spaces"),
        ("worker pid=4242 exited", "worker pid=<N> exited"),
    ],
)
def test_normalize(message, expected):
    assert normalize_message(message) == expected


def test_words_with_digits_are_kept():
    # ssh2, sda1, utf8 no son variables: no se tocan
    assert normalize_message("ssh2 on sda1 utf8") == "ssh2 on sda1 utf8"


def test_same_error_same_signature():
    a = 'ERROR: duplicate key "orders_pkey" Key (id)=(885123) already exists.'
    b = 'ERROR: duplicate key "orders_pkey" Key (id)=(899001) already exists.'
    assert signature_of(a) == signature_of(b)


def test_different_errors_different_signature():
    assert signature_of("disk full on /var") != signature_of("disk full on /home")


def test_category_namespaces_signature():
    msg = "connection refused"
    assert signature_of(msg, "http_error") != signature_of(msg, "application_error")
    assert len(signature_of(msg)) == 16

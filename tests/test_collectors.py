"""Collectors SSH y WinRM con clientes falsos (sin red)."""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

import pytest

from loganalyzer.collectors import CollectorError, StoredState, build_collector
from loganalyzer.collectors.ssh import SshCollector, build_journalctl_command
from loganalyzer.collectors.winrm import (
    WinRmCollector,
    build_ps_script,
    build_xpath,
    parse_ps_output,
)
from loganalyzer.config import HostConfig, WindowsChannel
from loganalyzer.models import Category

AUTH = (
    "Oct 28 12:00:01 web-01 sshd[10]: Failed password for root from 203.0.113.45 port 4000 ssh2\n"
    "Oct 28 12:00:02 web-01 sshd[11]: Accepted publickey for deploy from 10.0.0.5 port 4001 ssh2\n"
)
JOURNAL = "\n".join(
    json.dumps(
        {
            "__CURSOR": f"cursor-{i}",
            "__REALTIME_TIMESTAMP": str(1793188800000000 + i * 1_000_000),
            "_HOSTNAME": "db-01",
            "SYSLOG_IDENTIFIER": "postgres",
            "PRIORITY": "3",
            "MESSAGE": f"ERROR: deadlock detected pid {i}",
        }
    )
    for i in range(3)
)


# ---------------------------------------------------------------- fake paramiko


class _Channel:
    def __init__(self, rc: int) -> None:
        self.rc = rc

    def recv_exit_status(self) -> int:
        return self.rc


class _Stream:
    def __init__(self, data: bytes, rc: int = 0) -> None:
        self.data = data
        self.channel = _Channel(rc)

    def read(self) -> bytes:
        return self.data


class FakeSSHClient:
    """Imita paramiko.SSHClient interpretando los comandos que emite el collector."""

    def __init__(self, files: dict[str, tuple[str, bytes]], journal: str = "") -> None:
        self.files = files
        self.journal = journal
        self.commands: list[str] = []
        self.connected_with: dict = {}
        self.closed = False
        self.policy = None

    def load_system_host_keys(self):
        pass

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connected_with = kwargs

    def close(self):
        self.closed = True

    def exec_command(self, command: str, timeout: float | None = None):
        self.commands.append(command)
        cmd = command.removeprefix("sudo -n ")
        if cmd.startswith("stat "):
            path = shlex.split(cmd)[-1]
            if path not in self.files:
                return None, _Stream(b"", 1), _Stream(b"No such file")
            inode, data = self.files[path]
            return None, _Stream(f"{inode} {len(data)}\n".encode()), _Stream(b"")
        if m := re.match(r"tail -c \+(\d+) -- (.+?) \| head -c (\d+)", cmd):
            start, path, size = int(m[1]) - 1, shlex.split(m[2])[0], int(m[3])
            data = self.files[path][1][start : start + size]
            return None, _Stream(data), _Stream(b"")
        if cmd.startswith("journalctl"):
            lines = self.journal.splitlines()
            if m := re.search(r"--after-cursor=(\S+)", cmd):
                cursor = shlex.split(m[1])[0]
                idx = next(i for i, ln in enumerate(lines) if json.loads(ln)["__CURSOR"] == cursor)
                lines = lines[idx + 1 :]
            return None, _Stream("\n".join(lines).encode()), _Stream(b"")
        return None, _Stream(b"", 127), _Stream(b"command not found")


def ssh_host(**overrides) -> HostConfig:
    data = {
        "name": "web-01",
        "type": "ssh",
        "address": "10.0.0.11",
        "sudo": True,
        "credentials": {"username_env": "T_SSH_USER", "password_env": "T_SSH_PASS"},
        "files": [{"path": "/var/log/auth.log", "format": "auth"}],
    }
    data.update(overrides)
    return HostConfig(**data)


@pytest.fixture
def ssh_env(monkeypatch):
    monkeypatch.setenv("T_SSH_USER", "collector")
    monkeypatch.setenv("T_SSH_PASS", "secreto")


class TestSsh:
    def test_reads_file_incrementally(self, ssh_env):
        files = {"/var/log/auth.log": ("4242", AUTH.encode())}
        client = FakeSSHClient(files)
        collector = SshCollector(ssh_host(), client_factory=lambda: client)

        result = collector.collect(lambda key: None)
        assert [e.category for e in result.events] == [Category.AUTH_FAILURE, Category.AUTH_SUCCESS]
        assert client.connected_with["username"] == "collector"
        assert client.connected_with["password"] == "secreto"
        assert client.connected_with["look_for_keys"] is False
        assert client.closed
        assert all(c.startswith("sudo -n ") for c in client.commands)
        state = result.states[0]
        assert state.inode == "4242" and state.offset == len(AUTH.encode())

        # Segunda corrida: sin datos nuevos no hay eventos
        stored = StoredState(state.offset, state.inode)
        client2 = FakeSSHClient(files)
        again = SshCollector(ssh_host(), client_factory=lambda: client2).collect(lambda k: stored)
        assert again.events == []

    def test_paths_are_shell_quoted(self, ssh_env):
        path = "/var/log/my app.log"
        client = FakeSSHClient({path: ("1", AUTH.encode())})
        host = ssh_host(files=[{"path": path, "format": "auth"}])
        result = SshCollector(host, client_factory=lambda: client).collect(lambda k: None)
        assert len(result.events) == 2
        assert any("'/var/log/my app.log'" in c for c in client.commands)

    def test_missing_file_is_not_fatal(self, ssh_env):
        client = FakeSSHClient({})
        result = SshCollector(ssh_host(), client_factory=lambda: client).collect(lambda k: None)
        assert result.events == [] and "no existe" in result.notes[0]

    def test_journald_cursor(self, ssh_env):
        client = FakeSSHClient({}, journal=JOURNAL)
        host = ssh_host(files=[], journald={"enabled": True, "units": ["postgresql.service"]})
        result = SshCollector(host, client_factory=lambda: client).collect(lambda k: None)
        assert len(result.events) == 3
        assert result.events[0].category == Category.APPLICATION_ERROR
        assert result.states[0].cursor == "cursor-2"
        assert "--since=-1h" in client.commands[0]
        assert "-u postgresql.service" in client.commands[0]

        stored = StoredState(cursor="cursor-0")
        client2 = FakeSSHClient({}, journal=JOURNAL)
        result2 = SshCollector(host, client_factory=lambda: client2).collect(lambda k: stored)
        assert len(result2.events) == 2
        assert "--after-cursor=cursor-0" in client2.commands[0]

    def test_missing_credentials(self, monkeypatch):
        monkeypatch.delenv("T_SSH_USER", raising=False)
        collector = SshCollector(ssh_host(), client_factory=lambda: FakeSSHClient({}))
        with pytest.raises(CollectorError, match="T_SSH_USER"):
            collector.collect(lambda k: None)

    def test_reject_policy_by_default(self, ssh_env):
        import paramiko

        client = FakeSSHClient({})
        SshCollector(ssh_host(files=[]), client_factory=lambda: client).collect(lambda k: None)
        assert isinstance(client.policy, paramiko.RejectPolicy)

    def test_journalctl_command_quotes_cursor(self):
        cmd = build_journalctl_command("s=1;i=2", [], "-1h")
        assert "--after-cursor='s=1;i=2'" in cmd


# ---------------------------------------------------------------- fake pywinrm


@dataclass
class FakeResponse:
    status_code: int
    std_out: bytes
    std_err: bytes = b""


def win_event(record_id: int, event_id: int = 4625, log: str = "Security", **data) -> dict:
    return {
        "RecordId": record_id,
        "Id": event_id,
        "LogName": log,
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Level": 0,
        "TimeCreated": "2026-10-28T12:00:00.0000000Z",
        "MachineName": "DC-01",
        "Message": "An account failed to log on.",
        "Data": data or {"TargetUserName": "jperez", "IpAddress": "198.51.100.23"},
    }


class FakeWinRmSession:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self.responses = responses
        self.scripts: list[str] = []

    def run_ps(self, script: str) -> FakeResponse:
        self.scripts.append(script)
        for log, response in self.responses.items():
            if f"-LogName '{log}'" in script:
                return response
        return FakeResponse(0, b"[]")


def win_host(**overrides) -> HostConfig:
    data = {
        "name": "dc-01",
        "type": "winrm",
        "address": "dc-01.corp.example",
        "credentials": {"username_env": "T_WIN_USER", "password_env": "T_WIN_PASS"},
        "channels": [
            {"log": "Security", "event_ids": [4625, 4624, 4740]},
            {"log": "System", "event_ids": [7034]},
        ],
    }
    data.update(overrides)
    return HostConfig(**data)


@pytest.fixture
def win_env(monkeypatch):
    monkeypatch.setenv("T_WIN_USER", r"CORP\svc-logs")
    monkeypatch.setenv("T_WIN_PASS", "secreto")


class TestWinRm:
    def test_collect_with_bookmark(self, win_env):
        payload = json.dumps([win_event(101), win_event(103), win_event(102)]).encode("utf-8-sig")
        session = FakeWinRmSession({"Security": FakeResponse(0, payload)})
        captured = {}

        def factory(host, user, password):
            captured.update(user=user, password=password)
            return session

        prev = {"dc-01|winevent|Security": StoredState(cursor="100")}
        result = WinRmCollector(win_host(), session_factory=factory).collect(prev.get)
        assert captured == {"user": r"CORP\svc-logs", "password": "secreto"}
        assert len(result.events) == 3
        assert all(e.host == "dc-01" for e in result.events)
        sec_state = next(s for s in result.states if s.key.endswith("Security"))
        assert sec_state.cursor == "103"
        assert "EventRecordID > 100" in session.scripts[0]
        # System no devolvió nada y no tenía bookmark: no se guarda estado
        assert not any(s.key.endswith("System") for s in result.states)

    def test_single_object_output(self, win_env):
        payload = json.dumps(win_event(7, 7034, "System", param1="Spooler")).encode()
        session = FakeWinRmSession({"System": FakeResponse(0, payload)})
        result = WinRmCollector(win_host(), session_factory=lambda *a: session).collect(
            lambda k: None
        )
        assert len(result.events) == 1
        assert result.events[0].category == Category.SERVICE_CRASH

    def test_error_status_is_reported_per_channel(self, win_env):
        session = FakeWinRmSession(
            {
                "Security": FakeResponse(1, b"", b"Access is denied"),
                "System": FakeResponse(0, b"[]"),
            }
        )
        result = WinRmCollector(win_host(), session_factory=lambda *a: session).collect(
            lambda k: None
        )
        assert result.errors == ["Security: Get-WinEvent falló: Access is denied"]

    def test_initial_position_end_sets_bookmark_only(self, win_env):
        class LatestSession(FakeWinRmSession):
            def run_ps(self, script):
                self.scripts.append(script)
                return FakeResponse(0, b"88420\r\n")

        session = LatestSession({})
        host = win_host(initial_position="end", channels=[{"log": "Security", "event_ids": [4625]}])
        result = WinRmCollector(host, session_factory=lambda *a: session).collect(lambda k: None)
        assert result.events == []
        assert result.states[0].cursor == "88420"

    def test_missing_credentials(self, monkeypatch):
        monkeypatch.delenv("T_WIN_USER", raising=False)
        with pytest.raises(CollectorError):
            WinRmCollector(win_host(), session_factory=lambda *a: None).collect(lambda k: None)


def test_build_xpath():
    channel = WindowsChannel(log="Security", event_ids=[4625, 4740])
    assert build_xpath(channel, None) == "*[System[(EventID=4625 or EventID=4740)]]"
    assert build_xpath(channel, 55) == (
        "*[System[(EventID=4625 or EventID=4740) and EventRecordID > 55]]"
    )
    assert build_xpath(WindowsChannel(log="Application", levels=[1, 2]), None) == (
        "*[System[(Level=1 or Level=2)]]"
    )
    assert build_xpath(WindowsChannel(log="X"), None) == "*"


def test_ps_script_escapes_log_name():
    script = build_ps_script(WindowsChannel(log="O'Brien Log"), 10, max_events=50)
    assert "-LogName 'O''Brien Log'" in script
    assert "-MaxEvents 50 -Oldest" in script
    assert "EventRecordID > 10" in script


def test_parse_ps_output_variants():
    assert parse_ps_output(b"") == []
    assert parse_ps_output(b"\xef\xbb\xbf[]") == []
    assert parse_ps_output(b'{"Id": 1}') == [{"Id": 1}]
    assert parse_ps_output(b'[{"Id": 1}, null]') == [{"Id": 1}]


def test_build_collector_dispatch():
    assert (
        build_collector(HostConfig(name="a", type="local")).__class__.__name__ == "LocalCollector"
    )
    with pytest.raises(ValueError, match="address"):
        build_collector(HostConfig(name="b", type="ssh"))

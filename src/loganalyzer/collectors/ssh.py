"""Collector SSH para hosts Linux (paramiko).

No se copia el archivo completo: se usa `stat` para inode/tamaño y
`tail -c +N | head -c M` para traer solo los bytes nuevos. journald se lee con
`journalctl -o json --after-cursor`, guardando el último cursor.
"""

from __future__ import annotations

import logging
import shlex
from collections.abc import Callable
from typing import Any

from loganalyzer.collectors.base import (
    CollectorError,
    CollectResult,
    StateLookup,
    StateUpdate,
    tail_file,
)
from loganalyzer.collectors.local import state_key
from loganalyzer.config import HostConfig
from loganalyzer.parsers import ParseContext
from loganalyzer.parsers.journald import parse_journald_json

log = logging.getLogger(__name__)


def _default_client_factory() -> Any:
    import paramiko

    return paramiko.SSHClient()


class RemoteShell:
    """Ejecuta comandos sobre un cliente con la interfaz de paramiko.SSHClient."""

    def __init__(self, client: Any, sudo: bool = False, timeout: float = 30.0) -> None:
        self.client = client
        self.sudo = sudo
        self.timeout = timeout

    def run(self, command: str, *, privileged: bool = False) -> tuple[int, bytes, bytes]:
        if privileged and self.sudo:
            # -n: nunca pedir password; si sudo no está configurado falla rápido
            command = f"sudo -n {command}"
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
        out = stdout.read()
        err = stderr.read()
        rc = stdout.channel.recv_exit_status()
        return rc, out, err


class SshFileAccess:
    def __init__(self, shell: RemoteShell) -> None:
        self.shell = shell

    def stat(self, path: str) -> tuple[str, int] | None:
        rc, out, _ = self.shell.run(f"stat -L -c '%i %s' -- {shlex.quote(path)}", privileged=True)
        if rc != 0:
            return None
        inode, size = out.decode().split()
        return inode, int(size)

    def read(self, path: str, offset: int, max_bytes: int) -> bytes:
        cmd = f"tail -c +{offset + 1} -- {shlex.quote(path)}"
        if self.shell.sudo:
            cmd = f"sudo -n {cmd}"
        rc, out, err = self.shell.run(f"{cmd} | head -c {int(max_bytes)}")
        if rc != 0:
            raise CollectorError(f"lectura de {path} falló: {err.decode(errors='replace').strip()}")
        return out


def build_journalctl_command(cursor: str | None, units: list[str], since: str) -> str:
    parts = ["journalctl", "-o", "json", "--no-pager", "-q"]
    for unit in units:
        parts += ["-u", shlex.quote(unit)]
    if cursor:
        parts.append(f"--after-cursor={shlex.quote(cursor)}")
    else:
        parts.append(f"--since={shlex.quote(since)}")
    return " ".join(parts)


class SshCollector:
    def __init__(
        self,
        host: HostConfig,
        client_factory: Callable[[], Any] = _default_client_factory,
        chunk_size: int = 1024 * 1024,
        strict_host_keys: bool = True,
    ) -> None:
        if not host.address:
            raise ValueError(f"host {host.name}: falta 'address'")
        self.host = host
        self.client_factory = client_factory
        self.chunk_size = chunk_size
        self.strict_host_keys = strict_host_keys

    def _connect(self) -> Any:
        import paramiko

        username, password, key_file = self.host.credentials.resolve()
        if not username:
            env_name = self.host.credentials.username_env
            raise CollectorError(f"host {self.host.name}: falta la variable de entorno {env_name}")
        client = self.client_factory()
        client.load_system_host_keys()
        # Por defecto se rechazan hosts desconocidos (evita MITM). AutoAdd solo para labs.
        policy = paramiko.RejectPolicy() if self.strict_host_keys else paramiko.AutoAddPolicy()
        client.set_missing_host_key_policy(policy)
        client.connect(
            hostname=self.host.address,
            port=self.host.port or 22,
            username=username,
            password=password,
            key_filename=key_file,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def collect(self, get_state: StateLookup) -> CollectResult:
        result = CollectResult(host=self.host.name)
        client = self._connect()
        try:
            shell = RemoteShell(client, sudo=self.host.sudo)
            self._collect_files(shell, get_state, result)
            if self.host.journald.enabled:
                self._collect_journald(shell, get_state, result)
        finally:
            client.close()
        return result

    def _collect_files(self, shell: RemoteShell, get_state: StateLookup, result: CollectResult):
        access = SshFileAccess(shell)
        ctx = ParseContext(host=self.host.name, tz=self.host.tz)
        for source in self.host.files:
            key = state_key(self.host.name, source.path)
            try:
                outcome = tail_file(
                    access,
                    source.path,
                    source.format,
                    get_state(key),
                    ctx,
                    initial_position=self.host.initial_position,
                    chunk_size=self.chunk_size,
                )
            except CollectorError as exc:
                result.errors.append(str(exc))
                continue
            result.events.extend(outcome.events)
            result.lines_read += outcome.lines
            result.unparsed += outcome.unparsed
            if outcome.note:
                result.notes.append(outcome.note)
            result.states.append(
                StateUpdate(key, self.host.name, outcome.state.offset, outcome.state.inode)
            )

    def _collect_journald(self, shell: RemoteShell, get_state: StateLookup, result: CollectResult):
        key = f"{self.host.name}|journald"
        prev = get_state(key)
        cmd = build_journalctl_command(
            prev.cursor if prev else None,
            self.host.journald.units,
            self.host.journald.initial_since,
        )
        rc, out, err = shell.run(cmd, privileged=True)
        if rc != 0:
            result.errors.append(f"journalctl rc={rc}: {err.decode(errors='replace').strip()}")
            return
        cursor = prev.cursor if prev else None
        for line in out.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            result.lines_read += 1
            event = parse_journald_json(line, host=self.host.name)
            if event is None:
                result.unparsed += 1
                continue
            result.events.append(event)
            cursor = event.fields.get("cursor", cursor)
        result.states.append(StateUpdate(key, self.host.name, cursor=cursor))

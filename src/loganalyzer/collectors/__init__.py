"""Collectors: local, SSH (Linux) y WinRM (Windows)."""

from __future__ import annotations

from loganalyzer.collectors.base import (
    Collector,
    CollectorError,
    CollectResult,
    StateUpdate,
    StoredState,
)
from loganalyzer.collectors.local import LocalCollector
from loganalyzer.collectors.ssh import SshCollector
from loganalyzer.collectors.winrm import WinRmCollector
from loganalyzer.config import HostConfig


def build_collector(host: HostConfig, chunk_size: int = 1024 * 1024) -> Collector:
    if host.type == "local":
        return LocalCollector(host, chunk_size=chunk_size)
    if host.type == "ssh":
        return SshCollector(host, chunk_size=chunk_size, strict_host_keys=host.strict_host_keys)
    if host.type == "winrm":
        return WinRmCollector(host)
    raise ValueError(f"tipo de host no soportado: {host.type}")


__all__ = [
    "CollectResult",
    "Collector",
    "CollectorError",
    "LocalCollector",
    "SshCollector",
    "StateUpdate",
    "StoredState",
    "WinRmCollector",
    "build_collector",
]

"""Collector de archivos locales. Sirve para la demo y para hosts donde el
analizador corre junto a los logs (ej. un rsyslog central)."""

from __future__ import annotations

import os

from loganalyzer.collectors.base import CollectResult, StateLookup, StateUpdate, tail_file
from loganalyzer.config import HostConfig
from loganalyzer.parsers import ParseContext


class LocalFileAccess:
    def stat(self, path: str) -> tuple[str, int] | None:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return None
        return str(st.st_ino), st.st_size

    def read(self, path: str, offset: int, max_bytes: int) -> bytes:
        with open(path, "rb") as fh:
            fh.seek(offset)
            return fh.read(max_bytes)


def state_key(host: str, path: str) -> str:
    return f"{host}|file|{path}"


class LocalCollector:
    def __init__(self, host: HostConfig, chunk_size: int = 1024 * 1024) -> None:
        self.host = host
        self.chunk_size = chunk_size
        self.access = LocalFileAccess()

    def collect(self, get_state: StateLookup) -> CollectResult:
        result = CollectResult(host=self.host.name)
        ctx = ParseContext(host=self.host.name, tz=self.host.tz)
        for source in self.host.files:
            key = state_key(self.host.name, source.path)
            try:
                outcome = tail_file(
                    self.access,
                    source.path,
                    source.format,
                    get_state(key),
                    ctx,
                    initial_position=self.host.initial_position,
                    chunk_size=self.chunk_size,
                )
            except OSError as exc:
                result.errors.append(f"{source.path}: {exc}")
                continue
            result.events.extend(outcome.events)
            result.lines_read += outcome.lines
            result.unparsed += outcome.unparsed
            if outcome.note:
                result.notes.append(outcome.note)
            result.states.append(
                StateUpdate(
                    key, self.host.name, offset=outcome.state.offset, inode=outcome.state.inode
                )
            )
        return result

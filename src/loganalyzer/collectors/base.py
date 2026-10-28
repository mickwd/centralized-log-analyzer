"""Piezas comunes a todos los collectors: estado, planificación de lectura
incremental y detección de rotación.

La lógica de offsets es pura (no toca disco ni red) para poder testearla sin
archivos reales. Local y SSH solo cambian cómo se hace `stat` y `read`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from loganalyzer.models import LogEvent
from loganalyzer.parsers import ParseContext, get_parser

log = logging.getLogger(__name__)


class CollectorError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredState:
    offset: int = 0
    inode: str | None = None
    cursor: str | None = None


@dataclass(frozen=True)
class StateUpdate:
    key: str
    host: str
    offset: int = 0
    inode: str | None = None
    cursor: str | None = None


@dataclass
class CollectResult:
    host: str
    events: list[LogEvent] = field(default_factory=list)
    states: list[StateUpdate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    lines_read: int = 0
    unparsed: int = 0
    notes: list[str] = field(default_factory=list)


StateLookup = Callable[[str], StoredState | None]


class Collector(Protocol):
    def collect(self, get_state: StateLookup) -> CollectResult: ...


# ---------------------------------------------------------------- lógica pura


@dataclass(frozen=True)
class ReadPlan:
    start: int
    rotated: bool = False
    truncated: bool = False


def plan_read(
    prev: StoredState | None, inode: str, size: int, initial_position: str = "beginning"
) -> ReadPlan:
    """Decide desde qué byte leer.

    - Primera vez: desde 0 o desde el final según `initial_position`.
    - Cambió el inode: el archivo fue rotado (logrotate create) -> desde 0.
    - El tamaño es menor al offset: fue truncado (copytruncate) -> desde 0.
    - Si no, seguimos desde el offset guardado.
    """
    if prev is None or (prev.inode is None and prev.offset == 0):
        return ReadPlan(start=0 if initial_position == "beginning" else size)
    if prev.inode is not None and prev.inode != inode:
        return ReadPlan(start=0, rotated=True)
    if size < prev.offset:
        return ReadPlan(start=0, truncated=True)
    return ReadPlan(start=prev.offset)


def split_complete_lines(data: bytes, *, at_eof_limit: bool = False) -> tuple[list[str], int]:
    """Separa líneas completas. Una línea a medio escribir queda para la próxima lectura.

    Si el buffer está lleno y no hay ningún salto de línea (línea gigante) se
    consume igual con `at_eof_limit=True` para no quedar trabados para siempre.
    """
    idx = data.rfind(b"\n")
    if idx == -1:
        if at_eof_limit and data:
            return [data.decode("utf-8", errors="replace")], len(data)
        return [], 0
    chunk = data[: idx + 1]
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    return lines, idx + 1


# ---------------------------------------------------------------- tail genérico


class FileAccess(Protocol):
    def stat(self, path: str) -> tuple[str, int] | None:
        """Devuelve (inode, tamaño) o None si el archivo no existe."""

    def read(self, path: str, offset: int, max_bytes: int) -> bytes: ...


@dataclass
class TailOutcome:
    events: list[LogEvent]
    state: StoredState
    lines: int = 0
    unparsed: int = 0
    note: str | None = None


def _read_lines(
    access: FileAccess, path: str, start: int, chunk_size: int, max_chunks: int
) -> tuple[list[str], int]:
    lines: list[str] = []
    offset = start
    for _ in range(max_chunks):
        data = access.read(path, offset, chunk_size)
        if not data:
            break
        new_lines, consumed = split_complete_lines(data, at_eof_limit=len(data) >= chunk_size)
        lines.extend(new_lines)
        offset += consumed
        if consumed == 0 or len(data) < chunk_size:
            break
    return lines, offset


def tail_file(
    access: FileAccess,
    path: str,
    fmt: str,
    prev: StoredState | None,
    ctx: ParseContext,
    *,
    initial_position: str = "beginning",
    chunk_size: int = 1024 * 1024,
    max_chunks: int = 20,
) -> TailOutcome:
    info = access.stat(path)
    if info is None:
        # Archivo ausente (ej. justo durante la rotación): conservamos el estado
        return TailOutcome([], prev or StoredState(), note=f"{path}: no existe")
    inode, size = info
    plan = plan_read(prev, inode, size, initial_position)
    lines: list[str] = []
    note = None

    if plan.rotated and prev is not None:
        # logrotate con delaycompress deja el archivo viejo como <path>.1: leemos
        # lo que quedó sin procesar entre el último offset y la rotación.
        rotated_path = f"{path}.1"
        old = access.stat(rotated_path)
        if old is not None and old[0] == prev.inode and old[1] > prev.offset:
            tail_lines, _ = _read_lines(access, rotated_path, prev.offset, chunk_size, max_chunks)
            lines.extend(tail_lines)
            note = f"{path}: rotado, recuperadas {len(tail_lines)} líneas de {rotated_path}"
        else:
            note = f"{path}: rotado (no se encontró {rotated_path} con el inode anterior)"
    elif plan.truncated:
        note = f"{path}: truncado, se relee desde el inicio"

    new_lines, offset = _read_lines(access, path, plan.start, chunk_size, max_chunks)
    lines.extend(new_lines)

    parser = get_parser(fmt)
    events: list[LogEvent] = []
    unparsed = 0
    for line in lines:
        if not line.strip():
            continue
        event = parser(line, ctx)
        if event is None:
            unparsed += 1
            log.debug("línea no parseada en %s: %.200s", path, line)
            continue
        events.append(event)
    return TailOutcome(events, StoredState(offset=offset, inode=inode), len(lines), unparsed, note)

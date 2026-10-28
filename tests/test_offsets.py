"""Lectura incremental: offsets, inodes, rotación y truncado."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from loganalyzer.collectors.base import (
    StoredState,
    plan_read,
    split_complete_lines,
    tail_file,
)
from loganalyzer.collectors.local import LocalCollector, state_key
from loganalyzer.config import HostConfig
from loganalyzer.parsers import ParseContext

CTX = ParseContext(host="web-01", now=datetime(2026, 10, 28, 15, 0, tzinfo=UTC))
LINE = "Oct 28 12:00:{:02d} web-01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"


class FakeFS:
    """Sistema de archivos en memoria con inodes explícitos."""

    def __init__(self) -> None:
        self.files: dict[str, tuple[str, bytes]] = {}

    def write(self, path: str, data: str, inode: str = "100") -> None:
        self.files[path] = (inode, data.encode())

    def append(self, path: str, data: str) -> None:
        inode, current = self.files[path]
        self.files[path] = (inode, current + data.encode())

    def rotate(self, path: str, new_inode: str) -> None:
        self.files[f"{path}.1"] = self.files.pop(path)
        self.files[path] = (new_inode, b"")

    def stat(self, path: str):
        if path not in self.files:
            return None
        inode, data = self.files[path]
        return inode, len(data)

    def read(self, path: str, offset: int, max_bytes: int) -> bytes:
        return self.files[path][1][offset : offset + max_bytes]


class TestPlanRead:
    def test_first_time_beginning(self):
        assert plan_read(None, "1", 500).start == 0

    def test_first_time_end(self):
        assert plan_read(None, "1", 500, "end").start == 500

    def test_continue_from_offset(self):
        plan = plan_read(StoredState(offset=120, inode="1"), "1", 500)
        assert plan.start == 120
        assert not plan.rotated and not plan.truncated

    def test_rotation_by_inode(self):
        plan = plan_read(StoredState(offset=120, inode="1"), "2", 10)
        assert plan.start == 0 and plan.rotated

    def test_truncation(self):
        plan = plan_read(StoredState(offset=120, inode="1"), "1", 50)
        assert plan.start == 0 and plan.truncated

    def test_no_new_data(self):
        assert plan_read(StoredState(offset=500, inode="1"), "1", 500).start == 500


class TestSplitLines:
    def test_partial_last_line_is_kept_for_next_read(self):
        lines, consumed = split_complete_lines(b"uno\ndos\ntre")
        assert lines == ["uno", "dos"]
        assert consumed == len(b"uno\ndos\n")

    def test_no_newline(self):
        assert split_complete_lines(b"incompleta") == ([], 0)

    def test_giant_line_forced_when_buffer_full(self):
        lines, consumed = split_complete_lines(b"x" * 10, at_eof_limit=True)
        assert lines == ["x" * 10] and consumed == 10

    def test_crlf_and_invalid_utf8(self):
        lines, _ = split_complete_lines(b"a\r\nb\xff\n")
        assert lines == ["a", "b�"]


class TestTailFile:
    def test_incremental_reads(self):
        fs = FakeFS()
        fs.write("/var/log/auth.log", LINE.format(1) + LINE.format(2))
        out = tail_file(fs, "/var/log/auth.log", "auth", None, CTX)
        assert len(out.events) == 2
        assert out.state.inode == "100"

        fs.append("/var/log/auth.log", LINE.format(3))
        out2 = tail_file(fs, "/var/log/auth.log", "auth", out.state, CTX)
        assert len(out2.events) == 1
        assert out2.events[0].timestamp.second == 3

        out3 = tail_file(fs, "/var/log/auth.log", "auth", out2.state, CTX)
        assert out3.events == [] and out3.state == out2.state

    def test_partial_line_waits(self):
        fs = FakeFS()
        fs.write("/l", LINE.format(1) + LINE.format(2)[:20])
        out = tail_file(fs, "/l", "auth", None, CTX)
        assert len(out.events) == 1
        fs.append("/l", LINE.format(2)[20:])
        out2 = tail_file(fs, "/l", "auth", out.state, CTX)
        assert len(out2.events) == 1
        assert out2.events[0].timestamp.second == 2

    def test_rotation_recovers_tail_from_dot1(self):
        fs = FakeFS()
        fs.write("/l", LINE.format(1))
        out = tail_file(fs, "/l", "auth", None, CTX)
        # Llegan líneas nuevas y justo después rota, antes de la próxima lectura
        fs.append("/l", LINE.format(2))
        fs.rotate("/l", new_inode="200")
        fs.append("/l", LINE.format(3))
        out2 = tail_file(fs, "/l", "auth", out.state, CTX)
        assert [e.timestamp.second for e in out2.events] == [2, 3]
        assert out2.state.inode == "200"
        assert "rotado" in out2.note

    def test_rotation_without_dot1(self):
        fs = FakeFS()
        fs.write("/l", LINE.format(1))
        out = tail_file(fs, "/l", "auth", None, CTX)
        fs.write("/l", LINE.format(5), inode="300")
        out2 = tail_file(fs, "/l", "auth", out.state, CTX)
        assert [e.timestamp.second for e in out2.events] == [5]

    def test_copytruncate(self):
        fs = FakeFS()
        fs.write("/l", LINE.format(1) + LINE.format(2))
        out = tail_file(fs, "/l", "auth", None, CTX)
        fs.write("/l", LINE.format(9), inode="100")  # mismo inode, más chico
        out2 = tail_file(fs, "/l", "auth", out.state, CTX)
        assert [e.timestamp.second for e in out2.events] == [9]
        assert "truncado" in out2.note

    def test_missing_file_keeps_state(self):
        prev = StoredState(offset=10, inode="1")
        out = tail_file(FakeFS(), "/nope", "auth", prev, CTX)
        assert out.state == prev and out.events == []

    def test_reads_in_chunks(self):
        fs = FakeFS()
        fs.write("/l", "".join(LINE.format(i) for i in range(30)))
        out = tail_file(fs, "/l", "auth", None, CTX, chunk_size=200, max_chunks=100)
        assert len(out.events) == 30

    def test_chunk_limit_leaves_rest_for_next_cycle(self):
        fs = FakeFS()
        fs.write("/l", "".join(LINE.format(i) for i in range(30)))
        out = tail_file(fs, "/l", "auth", None, CTX, chunk_size=200, max_chunks=2)
        assert 0 < len(out.events) < 30
        out2 = tail_file(fs, "/l", "auth", out.state, CTX, chunk_size=10_000)
        assert len(out.events) + len(out2.events) == 30

    def test_unparsed_lines_counted(self):
        fs = FakeFS()
        fs.write("/l", LINE.format(1) + "basura\n\n")
        out = tail_file(fs, "/l", "auth", None, CTX)
        assert len(out.events) == 1 and out.unparsed == 1


@pytest.mark.skipif(not hasattr(os, "stat"), reason="requiere os.stat")
def test_local_collector_real_files_with_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(LINE.format(1), encoding="utf-8", newline="\n")
    host = HostConfig(name="web-01", type="local", files=[{"path": str(log), "format": "auth"}])
    states: dict[str, StoredState] = {}

    def run():
        result = LocalCollector(host).collect(states.get)
        for st in result.states:
            states[st.key] = StoredState(st.offset, st.inode, st.cursor)
        return result

    assert len(run().events) == 1
    with log.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(LINE.format(2))
    os.replace(log, tmp_path / "auth.log.1")  # rotación estilo logrotate "create"
    log.write_text(LINE.format(3), encoding="utf-8", newline="\n")

    result = run()
    assert [e.timestamp.second for e in result.events] == [2, 3]
    assert state_key("web-01", str(log)) in states

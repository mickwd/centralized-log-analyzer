from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from loganalyzer.cli import app
from loganalyzer.config import Settings
from loganalyzer.scheduler import build_scheduler, run_cycle
from loganalyzer.storage import repository as repo

ROOT = Path(__file__).resolve().parents[1]
AUTH = "".join(
    f"Oct 28 12:00:{i:02d} web-01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n"
    for i in range(15)
)


def _inventory(tmp_path: Path) -> Path:
    log = tmp_path / "auth.log"
    log.write_text(AUTH, encoding="utf-8")
    inv = tmp_path / "hosts.yaml"
    inv.write_text(
        "hosts:\n"
        "  - name: web-01\n"
        "    type: local\n"
        f"    files: [{{path: '{log.as_posix()}', format: auth}}]\n",
        encoding="utf-8",
    )
    return inv


def test_cli_collect_analyze_and_incidents(tmp_path):
    runner = CliRunner()
    db = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    inv = _inventory(tmp_path)

    result = runner.invoke(app, ["--database-url", db, "collect", "--inventory", str(inv)])
    assert result.exit_code == 0, result.output
    assert "web-01" in result.output

    rules = str(ROOT / "config" / "rules.yaml")
    result = runner.invoke(
        app, ["--database-url", db, "analyze", "--rules", rules, "--since-hours", "100000"]
    )
    assert result.exit_code == 0, result.output
    assert "incidentes nuevos: 1" in result.output

    result = runner.invoke(app, ["--database-url", db, "incidents"])
    assert "203.0.113.9" in result.output


def test_cli_collect_reports_errors_with_exit_code(tmp_path):
    inv = tmp_path / "hosts.yaml"
    inv.write_text("hosts:\n  - {name: w, type: winrm, address: x}\n", encoding="utf-8")
    db = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    result = CliRunner().invoke(app, ["--database-url", db, "collect", "--inventory", str(inv)])
    assert result.exit_code == 2


def test_run_cycle_and_scheduler(tmp_path, session_factory):
    settings = Settings(
        _env_file=None,
        database_url="sqlite://",
        inventory_path=_inventory(tmp_path),
        rules_path=ROOT / "config" / "rules.yaml",
        detection_lookback_minutes=60 * 24 * 3650,
    )
    run_cycle(settings, session_factory)
    with session_factory() as s:
        assert [i.rule_id for i in repo.list_incidents(s)] == ["ssh_bruteforce"]

    scheduler = build_scheduler(settings, session_factory)
    (job,) = scheduler.get_jobs()
    assert job.id == "collect_and_detect"
    assert job.trigger.interval.total_seconds() == settings.schedule_minutes * 60

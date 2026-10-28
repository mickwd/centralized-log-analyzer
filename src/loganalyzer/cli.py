"""CLI: `loganalyzer collect | analyze | serve | schedule | incidents | init-db`."""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import pandas as pd
import typer
from rich.console import Console
from rich.table import Table

from loganalyzer import analytics
from loganalyzer.config import Settings, get_settings, load_inventory
from loganalyzer.notifiers import build_notifiers
from loganalyzer.pipeline import incident_to_dict, run_collection, run_detection
from loganalyzer.rules import load_rules
from loganalyzer.storage import init_db, make_engine, make_session_factory
from loganalyzer.storage import repository as repo

app = typer.Typer(help="Analizador de logs centralizado", no_args_is_help=True)
console = Console()

SEVERITY_STYLE = {"low": "green", "medium": "yellow", "high": "dark_orange", "critical": "bold red"}


def _settings(ctx: typer.Context) -> Settings:
    return ctx.obj


def _session_factory(settings: Settings):
    engine = make_engine(settings.database_url)
    init_db(engine)
    return make_session_factory(engine)


@app.callback()
def main(
    ctx: typer.Context,
    database_url: Annotated[
        str | None, typer.Option(envvar="LOGAN_DATABASE_URL", help="URL SQLAlchemy")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = get_settings()
    if database_url:
        settings = settings.model_copy(update={"database_url": database_url})
    ctx.obj = settings


@app.command("init-db")
def init_db_cmd(ctx: typer.Context) -> None:
    """Crea las tablas en la base configurada."""
    settings = _settings(ctx)
    init_db(make_engine(settings.database_url))
    console.print(f"[green]Base inicializada[/] ({settings.database_url})")


@app.command()
def collect(
    ctx: typer.Context,
    inventory: Annotated[Path | None, typer.Option(help="Inventario YAML de hosts")] = None,
    host: Annotated[list[str] | None, typer.Option(help="Limitar a uno o más hosts")] = None,
) -> None:
    """Lee los logs nuevos de cada host (incremental) y los guarda."""
    settings = _settings(ctx)
    inv = load_inventory(inventory or settings.inventory_path)
    reports = run_collection(inv, _session_factory(settings), settings, only_hosts=host)

    table = Table(title="Recolección")
    for col in ("Host", "Líneas", "Eventos", "Sin parsear", "Estado"):
        table.add_column(
            col, justify="right" if col in ("Líneas", "Eventos", "Sin parsear") else "left"
        )
    for r in reports:
        status = "[red]" + "; ".join(r.errors) + "[/]" if r.errors else "[green]ok[/]"
        if r.notes:
            status += "\n[dim]" + "\n".join(r.notes) + "[/]"
        table.add_row(r.host, str(r.lines), str(r.events), str(r.unparsed), status)
    console.print(table)
    if any(r.errors for r in reports):
        raise typer.Exit(code=2)


def _print_df(title: str, df: pd.DataFrame, columns: list[str], max_width: int = 70) -> None:
    table = Table(title=title, title_justify="left")
    for col in columns:
        table.add_column(col, overflow="fold", max_width=max_width)
    if df.empty:
        table.add_row(*["-"] * len(columns))
    for _, row in df.iterrows():
        values = []
        for col in columns:
            value = row[col]
            if isinstance(value, pd.Timestamp):
                value = value.strftime("%Y-%m-%d %H:%M")
            values.append(str(value))
        table.add_row(*values)
    console.print(table)


@app.command()
def analyze(
    ctx: typer.Context,
    rules: Annotated[Path | None, typer.Option(help="Archivo de reglas YAML")] = None,
    since_hours: Annotated[int, typer.Option(help="Horas hacia atrás a evaluar")] = 24,
    detect: Annotated[bool, typer.Option(help="Ejecutar reglas y generar incidentes")] = True,
    top: Annotated[int, typer.Option(help="Filas por ranking")] = 10,
) -> None:
    """Corre las reglas de detección y muestra el reporte de analítica."""
    settings = _settings(ctx)
    factory = _session_factory(settings)
    now = datetime.now(UTC)
    since = now - timedelta(hours=since_hours)

    if detect:
        rule_list = load_rules(rules or settings.rules_path)
        report = run_detection(rule_list, factory, build_notifiers(settings), since=since)
        console.print(
            f"Reglas: {len(rule_list)} | eventos evaluados: {report.evaluated_events} | "
            f"candidatos: {report.candidates} | incidentes nuevos: {len(report.new_incidents)}"
        )

    with factory() as session:
        df = repo.events_dataframe(session, since=min(since, now - timedelta(days=8)))
        incidents = [incident_to_dict(r) for r in repo.list_incidents(session, "open", 50)]
    window_df = df[df["timestamp"] >= pd.Timestamp(since)] if not df.empty else df

    console.rule(f"Analítica ({since_hours} h)")
    console.print(
        f"Eventos: {len(window_df)} | por severidad: {analytics.severity_breakdown(window_df)}"
    )
    _print_df(
        "Top errores (por firma)",
        analytics.top_errors(window_df, top),
        ["count", "template", "hosts", "last_seen"],
    )
    _print_df(
        "Top IPs ofensivas",
        analytics.top_offending_ips(window_df, top),
        ["src_ip", "auth_failures", "http_errors", "hosts"],
    )
    pivot = analytics.errors_per_host_per_hour(window_df)
    if not pivot.empty:
        pivot = pivot.tail(12).reset_index()
        pivot["hour"] = pivot["hour"].dt.strftime("%m-%d %H:00")
        _print_df(
            "Errores por host por hora, UTC (últimas 12 h con datos)", pivot, list(pivot.columns)
        )
    _print_df(
        "Firmas nuevas (24 h vs 7 días previos)",
        analytics.new_signatures(df, now=now),
        ["count", "template", "hosts", "first_seen"],
    )

    table = Table(title="Incidentes abiertos", title_justify="left")
    for col in ("ID", "Severidad", "Regla", "Título", "Eventos", "Último"):
        table.add_column(col, overflow="fold")
    for inc in incidents:
        style = SEVERITY_STYLE.get(inc["severity"], "")
        table.add_row(
            str(inc["id"]),
            f"[{style}]{inc['severity']}[/]",
            inc["rule_id"],
            inc["title"],
            str(inc["count"]),
            inc["last_seen"][:19],
        )
    console.print(table)


@app.command()
def incidents(
    ctx: typer.Context,
    status: Annotated[str | None, typer.Option(help="open | acknowledged | resolved")] = "open",
) -> None:
    """Lista incidentes."""
    with _session_factory(_settings(ctx))() as session:
        for row in repo.list_incidents(session, status):
            console.print(
                f"#{row.id} [{SEVERITY_STYLE.get(row.severity, '')}]{row.severity}[/] "
                f"{row.title} ({row.count} eventos, último {row.last_seen:%Y-%m-%d %H:%M})"
            )


@app.command()
def serve(
    ctx: typer.Context,
    host: Annotated[str, typer.Option(help="Interfaz de escucha")] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8000,
    scheduler: Annotated[bool, typer.Option(help="Correr recolección periódica")] = False,
) -> None:
    """Levanta la API y el dashboard."""
    import uvicorn

    from loganalyzer.api import create_app

    settings = _settings(ctx)
    uvicorn.run(create_app(settings, start_scheduler=scheduler), host=host, port=port)


@app.command()
def schedule(ctx: typer.Context) -> None:
    """Corre recolección + detección cada LOGAN_SCHEDULE_MINUTES (bloqueante)."""
    from loganalyzer.scheduler import build_scheduler

    settings = _settings(ctx)
    console.print(f"Scheduler cada {settings.schedule_minutes} min. Ctrl+C para salir.")
    sched = build_scheduler(settings, _session_factory(settings), blocking=True)
    with contextlib.suppress(KeyboardInterrupt, SystemExit):
        sched.start()


if __name__ == "__main__":
    app()

"""Analítica con pandas sobre el DataFrame de eventos (ver repository.events_dataframe).

Las funciones son puras: reciben un DataFrame y devuelven otro, así se
reutilizan desde la CLI (reporte) y desde la API (dashboard).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pandas as pd

from loganalyzer.models import Category, Severity

_ERROR_LEVEL = Severity.ERROR.level


def _errors(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["severity_level"] >= _ERROR_LEVEL]


def _error_messages(df: pd.DataFrame) -> pd.DataFrame:
    """Errores con mensaje propio. Se excluyen los requests 5xx del access log:
    su "mensaje" es solo método + path y ya están cubiertos por la regla de pico
    de 5xx y por el gráfico de errores por hora."""
    errors = _errors(df)
    return errors[errors["category"] != Category.HTTP_ACCESS.value]


def top_errors(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Firmas de error más frecuentes con su plantilla, hosts afectados y rango temporal."""
    errors = _error_messages(df)
    if errors.empty:
        return pd.DataFrame(
            columns=[
                "signature",
                "template",
                "category",
                "count",
                "hosts",
                "first_seen",
                "last_seen",
            ]
        )
    grouped = (
        errors.groupby("signature")
        .agg(
            template=("template", "first"),
            category=("category", "first"),
            count=("id", "size"),
            hosts=("host", lambda s: ", ".join(sorted(s.unique()))),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
        .sort_values(["count", "last_seen"], ascending=[False, False])
    )
    return grouped.head(n).reset_index(drop=True)


def top_offending_ips(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """IPs con más fallos de autenticación + respuestas HTTP 4xx/5xx."""
    columns = ["src_ip", "auth_failures", "http_errors", "total", "hosts"]
    if df.empty:
        return pd.DataFrame(columns=columns)
    auth = df["category"] == Category.AUTH_FAILURE.value
    http = (df["category"] == Category.HTTP_ACCESS.value) & (df["status"].fillna(0) >= 400)
    bad = df[(auth | http) & df["src_ip"].notna()].copy()
    if bad.empty:
        return pd.DataFrame(columns=columns)
    bad["auth_failures"] = auth[bad.index].astype(int)
    bad["http_errors"] = http[bad.index].astype(int)
    grouped = (
        bad.groupby("src_ip")
        .agg(
            auth_failures=("auth_failures", "sum"),
            http_errors=("http_errors", "sum"),
            hosts=("host", lambda s: ", ".join(sorted(s.unique()))),
        )
        .reset_index()
    )
    grouped["total"] = grouped["auth_failures"] + grouped["http_errors"]
    grouped = grouped.sort_values("total", ascending=False)[columns]
    return grouped.head(n).reset_index(drop=True)


def errors_per_host_per_hour(df: pd.DataFrame) -> pd.DataFrame:
    """Tabla pivote: filas = hora (UTC), columnas = host, valores = cantidad de errores."""
    errors = _errors(df)
    if errors.empty:
        return pd.DataFrame()
    hours = errors["timestamp"].dt.floor("h")
    pivot = (
        errors.assign(hour=hours)
        .pivot_table(index="hour", columns="host", values="id", aggfunc="count", fill_value=0)
        .sort_index()
    )
    # Completar horas sin errores para que el gráfico no "salte" huecos
    full_index = pd.date_range(pivot.index.min(), pivot.index.max(), freq="h", tz="UTC")
    pivot = pivot.reindex(full_index, fill_value=0)
    pivot.index.name = "hour"
    pivot.columns.name = None
    return pivot.astype(int)


def new_signatures(
    df: pd.DataFrame,
    now: datetime | None = None,
    recent: timedelta = timedelta(hours=24),
    baseline: timedelta = timedelta(days=7),
) -> pd.DataFrame:
    """Firmas de error que aparecen en el período reciente y no se vieron en los
    `baseline` días anteriores. Útil para detectar regresiones después de un deploy."""
    now = now or datetime.now(UTC)
    columns = ["signature", "template", "count", "hosts", "first_seen"]
    errors = _error_messages(df)
    if errors.empty:
        return pd.DataFrame(columns=columns)
    recent_start = pd.Timestamp(now - recent)
    baseline_start = pd.Timestamp(now - recent - baseline)
    recent_df = errors[errors["timestamp"] >= recent_start]
    base_df = errors[(errors["timestamp"] >= baseline_start) & (errors["timestamp"] < recent_start)]
    known = set(base_df["signature"])
    fresh = recent_df[~recent_df["signature"].isin(known)]
    if fresh.empty:
        return pd.DataFrame(columns=columns)
    grouped = (
        fresh.groupby("signature")
        .agg(
            template=("template", "first"),
            count=("id", "size"),
            hosts=("host", lambda s: ", ".join(sorted(s.unique()))),
            first_seen=("timestamp", "min"),
        )
        .reset_index()
        .sort_values("count", ascending=False)
    )
    return grouped[columns].reset_index(drop=True)


def severity_breakdown(df: pd.DataFrame) -> dict[str, int]:
    if df.empty:
        return {}
    return {str(k): int(v) for k, v in df["severity"].value_counts().items()}

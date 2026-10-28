"""Motor de reglas. Recibe eventos y devuelve candidatos a incidente.

Es puro (sin DB): la deduplicación contra incidentes ya abiertos se hace al
persistir (`repository.upsert_incidents`). Acá solo se colapsan las ventanas
solapadas de un mismo grupo en un único "episodio".
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from loganalyzer.models import IncidentCandidate, LogEvent
from loganalyzer.rules.loader import Rule
from loganalyzer.signatures import normalize_message, signature_of

_PLACEHOLDER = re.compile(r"\{([\w.]+)\}")


@dataclass(frozen=True)
class Episode:
    start: datetime
    end: datetime
    count: int
    peak: int
    first_index: int
    last_index: int


def find_episodes(
    timestamps: Sequence[datetime], window: timedelta, min_count: int
) -> list[Episode]:
    """Busca tramos donde hay >= min_count eventos dentro de cualquier ventana de `window`.

    Ventana deslizante con dos punteros (O(n)). Las ventanas que se solapan se
    fusionan en un mismo episodio para no generar N incidentes por un mismo ataque.
    """
    episodes: list[Episode] = []
    left = 0
    start_idx = last_idx = peak = -1
    for right, ts in enumerate(timestamps):
        while timestamps[left] < ts - window:
            left += 1
        in_window = right - left + 1
        if in_window < min_count:
            continue
        if start_idx >= 0 and left <= last_idx:
            # La ventana actual se solapa con el episodio abierto: lo extendemos
            last_idx = right
            peak = max(peak, in_window)
            continue
        if start_idx >= 0:
            episodes.append(_episode(timestamps, start_idx, last_idx, peak))
        start_idx, last_idx, peak = left, right, in_window
    if start_idx >= 0:
        episodes.append(_episode(timestamps, start_idx, last_idx, peak))
    return episodes


def _episode(ts: Sequence[datetime], first: int, last: int, peak: int) -> Episode:
    return Episode(ts[first], ts[last], last - first + 1, peak, first, last)


def render_title(template: str, values: dict[str, Any]) -> str:
    return _PLACEHOLDER.sub(lambda m: str(values.get(m.group(1), m.group(0))), template)


def _group_events(rule: Rule, events: Iterable[LogEvent], group_by: list[str]):
    groups: dict[tuple[Any, ...], list[LogEvent]] = defaultdict(list)
    for event in events:
        if not rule.filter.matches(event):
            continue
        key = tuple(
            signature_of(event.message, event.category) if g == "signature" else event.field(g)
            for g in group_by
        )
        if any(v is None or v == "" for v in key):
            continue  # sin valor para agrupar (ej. logon local sin IP)
        groups[key].append(event)
    return groups


def _context(events: Sequence[LogEvent], episode: Episode, rule: Rule) -> dict[str, Any]:
    window_events = events[episode.first_index : episode.last_index + 1]
    ctx: dict[str, Any] = {
        "peak_in_window": episode.peak,
        "window_minutes": rule.window.total_seconds() / 60,
        "samples": [e.message for e in window_events[:3]],
    }
    users = sorted({str(e.fields["user"]) for e in window_events if e.fields.get("user")})
    if users:
        ctx["distinct_users"] = len(users)
        ctx["users"] = users[:10]
    hosts = sorted({e.host for e in window_events})
    ctx["hosts"] = hosts[:10]
    return ctx


def _evaluate_rule(rule: Rule, events: Sequence[LogEvent]) -> list[IncidentCandidate]:
    group_by = list(rule.group_by)
    if rule.type == "repeated_signature" and "signature" not in group_by:
        group_by.append("signature")
    min_count = 1 if rule.type == "match" else rule.min_count

    denominator: list[LogEvent] = []
    if rule.type == "ratio" and rule.denominator is not None:
        denominator = [e for e in events if rule.denominator.matches(e)]

    candidates: list[IncidentCandidate] = []
    for key, group in _group_events(rule, events, group_by).items():
        timestamps = [e.timestamp for e in group]
        values: dict[str, Any] = dict(zip(group_by, key, strict=True))
        for episode in find_episodes(timestamps, rule.window, min_count):
            ctx = _context(group, episode, rule)
            if rule.type == "ratio":
                total = _count_denominator(denominator, group_by, values, episode)
                ratio = episode.count / total if total else 1.0
                if ratio < (rule.min_ratio or 0):
                    continue
                ctx.update(total=total, ratio=round(ratio, 3))
            if rule.type == "repeated_signature":
                ctx["template"] = normalize_message(group[episode.first_index].message)
            hosts = ctx["hosts"]
            title_values = {
                **values,
                "count": episode.count,
                "window": _fmt_window(rule.window),
                "template": ctx.get("template", ""),
                "ratio": f"{ctx.get('ratio', 0):.0%}",
            }
            if len(hosts) == 1:
                title_values.setdefault("host", hosts[0])
            candidates.append(
                IncidentCandidate(
                    rule_id=rule.id,
                    dedup_key="|".join([rule.id, *(str(v) for v in key)]),
                    title=render_title(rule.title, title_values)[:500],
                    description=rule.description,
                    severity=rule.severity,
                    host=values.get("host") or (hosts[0] if len(hosts) == 1 else None),
                    first_seen=episode.start,
                    last_seen=episode.end,
                    count=episode.count,
                    context={"group": {k: str(v) for k, v in values.items()}, **ctx},
                    cooldown_minutes=int(rule.cooldown.total_seconds() // 60),
                )
            )
    return candidates


def _count_denominator(
    denominator: Sequence[LogEvent], group_by: list[str], values: dict[str, Any], ep: Episode
) -> int:
    """Total de eventos del mismo grupo en la ventana del episodio (para ratios)."""
    timestamps = [
        e.timestamp for e in denominator if all(e.field(g) == values[g] for g in group_by)
    ]
    return bisect_right(timestamps, ep.end) - bisect_left(timestamps, ep.start)


def _fmt_window(window: timedelta) -> str:
    minutes = int(window.total_seconds() // 60)
    return f"{minutes // 60}h" if minutes % 60 == 0 and minutes >= 60 else f"{minutes}m"


def evaluate(rules: Iterable[Rule], events: Iterable[LogEvent]) -> list[IncidentCandidate]:
    ordered = sorted(events, key=lambda e: e.timestamp)
    candidates: list[IncidentCandidate] = []
    for rule in rules:
        candidates.extend(_evaluate_rule(rule, ordered))
    return candidates

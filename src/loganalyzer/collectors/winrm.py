"""Collector WinRM para hosts Windows (pywinrm + Get-WinEvent).

Por cada canal (Security, System, Application) se guarda como bookmark el último
RecordId procesado. La consulta usa FilterXPath con `EventRecordID > N`, que el
servicio de Event Log resuelve del lado del servidor, y -Oldest para avanzar en
orden aunque haya más eventos que MaxEvents.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from loganalyzer.collectors.base import CollectorError, CollectResult, StateLookup, StateUpdate
from loganalyzer.config import HostConfig, WindowsChannel
from loganalyzer.parsers.windows import parse_windows_event

_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$xpath = "__XPATH__"
try {
    $events = @(Get-WinEvent -LogName '__LOG__' -FilterXPath $xpath -MaxEvents __MAX__ -Oldest)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() } else { throw }
}
$out = @(foreach ($e in $events) {
    $data = @{}
    $xml = [xml]$e.ToXml()
    foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = $d.'#text' } }
    $msg = $null
    if ($e.Message) { $msg = ($e.Message -split "`r?`n")[0] }
    [pscustomobject]@{
        RecordId     = $e.RecordId
        Id           = $e.Id
        LogName      = $e.LogName
        ProviderName = $e.ProviderName
        Level        = $e.Level
        TimeCreated  = $e.TimeCreated.ToUniversalTime().ToString('o')
        MachineName  = $e.MachineName
        Message      = $msg
        Data         = $data
    }
})
ConvertTo-Json -InputObject $out -Depth 4 -Compress
"""


def build_xpath(channel: WindowsChannel, after_record_id: int | None) -> str:
    clauses: list[str] = []
    if channel.event_ids:
        clauses.append("(" + " or ".join(f"EventID={i}" for i in channel.event_ids) + ")")
    if channel.levels:
        clauses.append("(" + " or ".join(f"Level={lv}" for lv in channel.levels) + ")")
    if after_record_id is not None:
        clauses.append(f"EventRecordID > {int(after_record_id)}")
    if not clauses:
        return "*"
    return f"*[System[{' and '.join(clauses)}]]"


def build_ps_script(
    channel: WindowsChannel, after_record_id: int | None, max_events: int = 1000
) -> str:
    """Script que trae hasta `max_events` eventos posteriores al bookmark, en orden cronológico."""
    log_name = channel.log.replace("'", "''")
    return (
        _PS_TEMPLATE.replace("__XPATH__", build_xpath(channel, after_record_id))
        .replace("__LOG__", log_name)
        .replace("__MAX__", str(int(max_events)))
        .strip()
    )


def parse_ps_output(stdout: bytes) -> list[dict[str, Any]]:
    text = stdout.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):  # PowerShell desarma arrays de un elemento
        data = [data]
    return [d for d in data if isinstance(d, dict)]


def _default_session_factory(host: HostConfig, username: str, password: str) -> Any:
    import winrm

    scheme = "https" if (host.port or 5986) == 5986 else "http"
    endpoint = f"{scheme}://{host.address}:{host.port or 5986}/wsman"
    return winrm.Session(
        endpoint,
        auth=(username, password),
        transport=host.transport,
        server_cert_validation="validate" if host.verify_tls else "ignore",
    )


class WinRmCollector:
    def __init__(
        self,
        host: HostConfig,
        session_factory: Callable[[HostConfig, str, str], Any] = _default_session_factory,
        max_events: int = 1000,
    ) -> None:
        if not host.address:
            raise ValueError(f"host {host.name}: falta 'address'")
        self.host = host
        self.session_factory = session_factory
        self.max_events = max_events

    def collect(self, get_state: StateLookup) -> CollectResult:
        username, password, _ = self.host.credentials.resolve()
        if not username or not password:
            raise CollectorError(f"host {self.host.name}: faltan credenciales WinRM en el entorno")
        session = self.session_factory(self.host, username, password)
        result = CollectResult(host=self.host.name)

        for channel in self.host.channels:
            key = f"{self.host.name}|winevent|{channel.log}"
            prev = get_state(key)
            bookmark = int(prev.cursor) if prev and prev.cursor else None

            if bookmark is None and self.host.initial_position == "end":
                bookmark = self._latest_record_id(session, channel)
                result.states.append(StateUpdate(key, self.host.name, cursor=str(bookmark or 0)))
                result.notes.append(f"{channel.log}: bookmark inicial en RecordId {bookmark}")
                continue

            response = session.run_ps(build_ps_script(channel, bookmark, self.max_events))
            if response.status_code != 0:
                err = response.std_err.decode("utf-8", errors="replace").strip()
                result.errors.append(f"{channel.log}: Get-WinEvent falló: {err[:500]}")
                continue

            raw_events = parse_ps_output(response.std_out)
            last = bookmark
            for raw in raw_events:
                result.lines_read += 1
                event = parse_windows_event(raw, host=self.host.name)
                if event is None:
                    result.unparsed += 1
                    continue
                result.events.append(event)
                record_id = raw.get("RecordId")
                if isinstance(record_id, int) and (last is None or record_id > last):
                    last = record_id
            if last is not None:
                result.states.append(StateUpdate(key, self.host.name, cursor=str(last)))
        return result

    def _latest_record_id(self, session: Any, channel: WindowsChannel) -> int | None:
        script = (
            f"$e = Get-WinEvent -LogName '{channel.log.replace(chr(39), chr(39) * 2)}' "
            "-MaxEvents 1 -ErrorAction SilentlyContinue; if ($e) { $e.RecordId }"
        )
        response = session.run_ps(script)
        text = response.std_out.decode(errors="replace").strip()
        return int(text) if text.isdigit() else None

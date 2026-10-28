"""Genera logs de ejemplo realistas en samples/ para correr la demo sin servidores.

Escenarios incluidos (relativos a la hora de ejecución):
  - web-01: tráfico nginx normal, fuerza bruta SSH desde 203.0.113.45,
            crash loop de app-worker.service y pico de 5xx con upstream caído.
  - db-01:  línea base de 8 días de errores de PostgreSQL (RFC5424) y, en las
            últimas horas, un error repetido nuevo (duplicate key) + journald.
  - dc-01:  eventos de Windows: password spraying (4625), bloqueos (4740),
            Print Spooler cayéndose (7034), apagado inesperado (6008).

Uso:
    python scripts/generate_samples.py [--out samples] [--seed 42] [--hours 6]

Solo usa la librería estándar.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

ART = timezone(timedelta(hours=-3))  # web-01 está configurado en America/Argentina/Buenos_Aires

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "okhttp/4.12.0",
    "curl/8.5.0",
]
PATHS = [
    ("GET", "/", 200),
    ("GET", "/productos", 200),
    ("GET", "/productos/1532", 200),
    ("GET", "/api/cart", 200),
    ("POST", "/api/cart/items", 201),
    ("GET", "/static/app.3f9c2a.js", 200),
    ("GET", "/static/styles.8a1b.css", 200),
    ("POST", "/api/checkout", 200),
    ("GET", "/api/health", 200),
    ("GET", "/favicon.ico", 404),
]
SCANNER_PATHS = ["/wp-login.php", "/.env", "/phpmyadmin/", "/.git/config", "/admin.php"]


class Timeline:
    """Acumula líneas (timestamp, texto) por archivo y las escribe ordenadas."""

    def __init__(self) -> None:
        self.files: dict[Path, list[tuple[datetime, str]]] = {}

    def add(self, path: Path, ts: datetime, line: str) -> None:
        self.files.setdefault(path, []).append((ts, line))

    def write(self) -> dict[Path, int]:
        counts = {}
        for path, lines in self.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            lines.sort(key=lambda x: x[0])
            with path.open("w", encoding="utf-8", newline="\n") as fh:
                fh.writelines(text + "\n" for _, text in lines)
            counts[path] = len(lines)
        return counts


def bsd(ts: datetime, host: str, tag: str, msg: str, tz: timezone = ART) -> str:
    local = ts.astimezone(tz)
    return f"{local:%b} {local.day:>2} {local:%H:%M:%S} {host} {tag}: {msg}"


def rfc5424(ts: datetime, host: str, app: str, pid: int, msg: str, sev: int, seq: int) -> str:
    pri = 16 * 8 + sev  # facility local0
    stamp = ts.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return f'<{pri}>1 {stamp} {host} {app} {pid} - [meta sequenceId="{seq}"] {msg}'


def nginx_access(ts: datetime, ip: str, method: str, path: str, status: int, rnd: random.Random):
    local = ts.astimezone(ART)
    size = 0 if status in (204, 304) else rnd.randint(180, 48000)
    ua = rnd.choice(USER_AGENTS)
    rt = rnd.uniform(0.002, 0.4) if status < 500 else rnd.uniform(5, 60)
    return (
        f'{ip} - - [{local:%d/%b/%Y:%H:%M:%S %z}] "{method} {path} HTTP/1.1" {status} {size} '
        f'"https://shop.example.com/" "{ua}" rt={rt:.3f}'
    )


def nginx_error(ts: datetime, level: str, msg: str, cid: int) -> str:
    local = ts.astimezone(ART)
    return f"{local:%Y/%m/%d %H:%M:%S} [{level}] 1187#1187: *{cid} {msg}"


def gen_web01(tl: Timeline, out: Path, end: datetime, hours: int, rnd: random.Random) -> None:
    start = end - timedelta(hours=hours)
    auth = out / "web-01" / "auth.log"
    syslog = out / "web-01" / "syslog"
    access = out / "web-01" / "nginx" / "access.log"
    error = out / "web-01" / "nginx" / "error.log"
    host = "web-01"
    pid = 20000

    # --- auth.log: logins legítimos + ruido de scanners
    t = start
    while t < end:
        pid += rnd.randint(3, 40)
        user = rnd.choice(["deploy", "jgomez", "monitoring"])
        tl.add(
            auth,
            t,
            bsd(
                t,
                host,
                f"sshd[{pid}]",
                f"Accepted publickey for {user} from 10.10.0.5 "
                f"port {rnd.randint(40000, 60000)} ssh2: ED25519 SHA256:q8n0Yk2c1VhR",
            ),
        )
        tl.add(
            auth,
            t,
            bsd(
                t,
                host,
                f"sshd[{pid}]",
                f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)",
            ),
        )
        t += timedelta(minutes=rnd.randint(15, 45))
    t = start
    while t < end:
        ip = f"45.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}"
        pid += 7
        tl.add(
            auth,
            t,
            bsd(
                t,
                host,
                f"sshd[{pid}]",
                f"Failed password for root from {ip} port {rnd.randint(30000, 65000)} ssh2",
            ),
        )
        t += timedelta(minutes=rnd.randint(8, 30))
    t = start + timedelta(minutes=1)
    while t < end:
        tl.add(
            auth,
            t,
            bsd(
                t,
                host,
                f"CRON[{pid}]",
                "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            ),
        )
        t += timedelta(hours=1)

    # --- fuerza bruta: 45 intentos en ~4 minutos
    bf_start = end - timedelta(minutes=150)
    attacker = "203.0.113.45"
    users = ["root", "admin", "oracle", "test", "ubuntu", "postgres", "git"]
    for i in range(45):
        t = bf_start + timedelta(seconds=i * 5 + rnd.randint(0, 3))
        user = rnd.choice(users)
        port = rnd.randint(30000, 65000)
        pid += 1
        if user in ("root", "ubuntu"):
            tl.add(
                auth,
                t,
                bsd(
                    t,
                    host,
                    f"sshd[{pid}]",
                    f"Failed password for {user} from {attacker} port {port} ssh2",
                ),
            )
        else:
            tl.add(
                auth,
                t,
                bsd(t, host, f"sshd[{pid}]", f"Invalid user {user} from {attacker} port {port}"),
            )
            tl.add(
                auth,
                t,
                bsd(
                    t,
                    host,
                    f"sshd[{pid}]",
                    f"Failed password for invalid user {user} from {attacker} port {port} ssh2",
                ),
            )
    t = bf_start + timedelta(minutes=4)
    tl.add(
        auth,
        t,
        bsd(
            t,
            host,
            f"sshd[{pid}]",
            f"error: maximum authentication attempts exceeded for root from {attacker} "
            f"port 51122 ssh2 [preauth]",
        ),
    )

    # --- syslog: actividad normal
    t = start
    while t < end:
        tl.add(
            syslog,
            t,
            bsd(
                t,
                host,
                f"CRON[{rnd.randint(1000, 9999)}]",
                "(root) CMD (/usr/local/bin/backup-check.sh > /dev/null 2>&1)",
            ),
        )
        t += timedelta(minutes=10)
    t = start + timedelta(minutes=3)
    while t < end:
        tl.add(
            syslog,
            t,
            bsd(t, host, "systemd[1]", "Starting logrotate.service - Rotate log files..."),
        )
        tl.add(
            syslog,
            t + timedelta(seconds=1),
            bsd(
                t + timedelta(seconds=1),
                host,
                "systemd[1]",
                "logrotate.service: Deactivated successfully.",
            ),
        )
        t += timedelta(hours=1)
    t = start + timedelta(minutes=17)
    while t < end:
        tl.add(
            syslog,
            t,
            bsd(
                t,
                host,
                "app-worker[812]",
                f"warning: job queue latency {rnd.randint(1200, 4000)} ms above target",
            ),
        )
        t += timedelta(minutes=rnd.randint(25, 70))

    # --- crash loop de app-worker: 8 caídas en ~9 minutes
    cl_start = end - timedelta(minutes=90)
    for n in range(1, 9):
        t = cl_start + timedelta(seconds=n * 65)
        wpid = 4100 + n * 13
        tl.add(
            syslog,
            t,
            bsd(
                t,
                host,
                f"app-worker[{wpid}]",
                "Error: connect ECONNREFUSED 10.10.0.21:5432 at TCPConnectWrap.afterConnect",
            ),
        )
        t2 = t + timedelta(seconds=1)
        tl.add(
            syslog,
            t2,
            bsd(
                t2,
                host,
                "systemd[1]",
                "app-worker.service: Main process exited, code=exited, status=1/FAILURE",
            ),
        )
        tl.add(
            syslog,
            t2,
            bsd(t2, host, "systemd[1]", "app-worker.service: Failed with result 'exit-code'."),
        )
        t3 = t + timedelta(seconds=6)
        tl.add(
            syslog,
            t3,
            bsd(
                t3,
                host,
                "systemd[1]",
                f"app-worker.service: Scheduled restart job, restart counter is at {n}.",
            ),
        )
        tl.add(
            syslog,
            t3,
            bsd(t3, host, "systemd[1]", "Started app-worker.service - App background worker."),
        )

    # --- nginx: tráfico normal (~8 req/min) + scanner + pico de 5xx
    spike_start = end - timedelta(minutes=45)
    spike_end = spike_start + timedelta(minutes=12)
    clients = [
        f"181.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}" for _ in range(60)
    ]
    t = start
    cid = 100000
    while t < end:
        in_spike = spike_start <= t < spike_end
        method, path, status = rnd.choice(PATHS)
        if in_spike and path.startswith("/api") and rnd.random() < 0.75:
            status = rnd.choice([502, 502, 504, 503])
        elif rnd.random() < 0.004:
            status = 500
        ip = rnd.choice(clients)
        tl.add(access, t, nginx_access(t, ip, method, path, status, rnd))
        if status in (502, 504):
            cid += 1
            if status == 502:
                msg = (
                    "connect() failed (111: Connection refused) while connecting to upstream, "
                    f'client: {ip}, server: shop.example.com, request: "{method} {path} HTTP/1.1", '
                    f'upstream: "http://127.0.0.1:8080{path}", host: "shop.example.com"'
                )
            else:
                msg = (
                    "upstream timed out (110: Connection timed out) while reading response header "
                    f'from upstream, client: {ip}, server: shop.example.com, request: "{method} '
                    f'{path} HTTP/1.1", upstream: "http://127.0.0.1:8080{path}", host: "shop.example.com"'
                )
            tl.add(error, t, nginx_error(t, "error", msg, cid))
        step = rnd.uniform(1, 6) if in_spike else rnd.uniform(3, 12)
        t += timedelta(seconds=step)
    scanner = "198.51.100.77"
    t = end - timedelta(minutes=200)
    for p in SCANNER_PATHS * 4:
        t += timedelta(seconds=rnd.randint(1, 4))
        tl.add(access, t, nginx_access(t, scanner, "GET", p, 404, rnd))
    # Línea base de 8 días: algún timeout aislado (no debe figurar como firma nueva)
    t = end - timedelta(days=8)
    while t < start:
        cid += 1
        ip = rnd.choice(clients)
        tl.add(
            error,
            t,
            nginx_error(
                t,
                "error",
                "upstream timed out (110: Connection timed out) while reading response header "
                f'from upstream, client: {ip}, server: shop.example.com, request: "GET /api/cart HTTP/1.1", '
                'upstream: "http://127.0.0.1:8080/api/cart", host: "shop.example.com"',
                cid,
            ),
        )
        t += timedelta(hours=rnd.randint(10, 30))
    t = start + timedelta(minutes=30)
    while t < end:
        cid += 1
        tl.add(
            error,
            t,
            nginx_error(
                t,
                "warn",
                "an upstream response is buffered to a temporary file "
                f"/var/cache/nginx/proxy_temp/{rnd.randint(1, 9)}/{rnd.randint(10, 99)}/00000{rnd.randint(10000, 99999)} "
                f"while reading upstream, client: {rnd.choice(clients)}, server: shop.example.com",
                cid,
            ),
        )
        t += timedelta(minutes=rnd.randint(30, 90))


def gen_db01(tl: Timeline, out: Path, end: datetime, hours: int, rnd: random.Random) -> None:
    syslog = out / "db-01" / "syslog"
    journal = out / "db-01" / "journal.json"
    host = "db-01"
    seq = 0

    def pg(ts: datetime, msg: str, sev: int) -> None:
        nonlocal seq
        seq += 1
        tl.add(syslog, ts, rfc5424(ts, host, "postgres", rnd.randint(2000, 9000), msg, sev, seq))

    # Línea base de 8 días: errores "conocidos"
    t = end - timedelta(days=8)
    while t < end:
        pg(t, "ERROR:  canceling statement due to statement timeout", 3)
        if rnd.random() < 0.5:
            pg(
                t + timedelta(minutes=3),
                f"LOG:  checkpoints are occurring too frequently ({rnd.randint(15, 29)} seconds apart)",
                4,
            )
        if rnd.random() < 0.3:
            pg(
                t + timedelta(minutes=7),
                f"ERROR:  could not serialize access due to concurrent update (xid {rnd.randint(10**6, 10**7)})",
                3,
            )
        t += timedelta(minutes=rnd.randint(90, 240))
    t = end - timedelta(hours=hours)
    while t < end:
        pg(
            t,
            f'LOG:  automatic vacuum of table "shop.public.orders": index scans: {rnd.randint(0, 2)}',
            6,
        )
        t += timedelta(minutes=rnd.randint(10, 30))

    # Error nuevo y repetido: 35 duplicados en ~10 min
    burst = end - timedelta(minutes=70)
    for i in range(35):
        ts = burst + timedelta(seconds=i * 17 + rnd.randint(0, 5))
        pg(
            ts,
            'ERROR:  duplicate key value violates unique constraint "orders_pkey" '
            f"DETAIL: Key (id)=({rnd.randint(880000, 899999)}) already exists.",
            3,
        )
    # Otro error nuevo, de baja frecuencia (aparece en "firmas nuevas" pero no dispara regla)
    for i in range(4):
        ts = end - timedelta(minutes=95 - i * 2)
        pg(
            ts,
            "FATAL:  remaining connection slots are reserved for non-replication superuser connections",
            2,
        )

    # journald: logins y timers de backup
    t = end - timedelta(hours=hours)
    cursor_seq = 0x1A2B00
    while t < end:
        for ident, msg, prio, unit in (
            (
                "sshd",
                f"Accepted publickey for dba from 10.10.0.5 port {rnd.randint(40000, 60000)} ssh2",
                6,
                "ssh.service",
            ),
            (
                "systemd",
                "Starting pg-backup.service - Nightly PostgreSQL backup...",
                6,
                "init.scope",
            ),
            (
                "pg-backup",
                f"backup finished: {rnd.randint(800, 1200)} MB in {rnd.randint(40, 90)} s",
                6,
                "pg-backup.service",
            ),
        ):
            cursor_seq += 1
            entry = {
                "__CURSOR": f"s=7d1c0e5a;i={cursor_seq:x};b=3f2a;m=1a2b;t={int(t.timestamp() * 1e6):x}",
                "__REALTIME_TIMESTAMP": str(int(t.timestamp() * 1_000_000)),
                "_HOSTNAME": host,
                "SYSLOG_IDENTIFIER": ident,
                "_SYSTEMD_UNIT": unit,
                "PRIORITY": str(prio),
                "_PID": str(rnd.randint(1000, 30000)),
                "MESSAGE": msg,
            }
            tl.add(journal, t, json.dumps(entry, separators=(",", ":")))
            t += timedelta(seconds=30)
        t += timedelta(minutes=rnd.randint(40, 80))


def gen_dc01(tl: Timeline, out: Path, end: datetime, hours: int, rnd: random.Random) -> None:
    path = out / "dc-01" / "windows-events.jsonl"
    record_ids = {"Security": 884200, "System": 15200, "Application": 40210}

    def ev(ts: datetime, log: str, event_id: int, level: int, provider: str, msg: str, data: dict):
        record_ids[log] += 1
        entry = {
            "RecordId": record_ids[log],
            "Id": event_id,
            "LogName": log,
            "ProviderName": provider,
            "Level": level,
            "TimeCreated": ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
            "MachineName": "DC-01.corp.example",
            "Message": msg,
            "Data": data,
        }
        tl.add(path, ts, json.dumps(entry, ensure_ascii=False))

    sec = "Microsoft-Windows-Security-Auditing"
    start = end - timedelta(hours=hours)
    staff = ["jperez", "mgarcia", "lrodriguez", "afernandez", "svc-backup"]

    t = start
    while t < end:
        user = rnd.choice(staff)
        ev(
            t,
            "Security",
            4624,
            0,
            sec,
            "An account was successfully logged on.",
            {
                "TargetUserName": user,
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": f"10.10.1.{rnd.randint(10, 200)}",
                "WorkstationName": f"PC-{rnd.randint(100, 199)}",
            },
        )
        t += timedelta(minutes=rnd.randint(2, 9))
    t = start
    while t < end:  # algún error de tipeo aislado
        ev(
            t,
            "Security",
            4625,
            0,
            sec,
            "An account failed to log on.",
            {
                "TargetUserName": rnd.choice(staff),
                "TargetDomainName": "CORP",
                "LogonType": "2",
                "IpAddress": "-",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "WorkstationName": "PC-131",
            },
        )
        t += timedelta(minutes=rnd.randint(40, 120))

    # Password spraying desde 198.51.100.23: 32 intentos en ~6 min contra varias cuentas
    spray = end - timedelta(minutes=200)
    for i in range(32):
        ts = spray + timedelta(seconds=i * 11)
        ev(
            ts,
            "Security",
            4625,
            0,
            sec,
            "An account failed to log on.",
            {
                "TargetUserName": staff[i % 4],
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": "198.51.100.23",
                "IpPort": str(rnd.randint(49000, 65000)),
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "WorkstationName": "KALI",
            },
        )
    for i, user in enumerate(["jperez", "mgarcia"]):
        ts = spray + timedelta(minutes=3, seconds=i * 40)
        ev(
            ts,
            "Security",
            4740,
            0,
            sec,
            "A user account was locked out.",
            {"TargetUserName": user, "TargetDomainName": "KALI", "SubjectUserName": "DC-01$"},
        )

    # Print Spooler cayéndose 4 veces en 8 minutos
    crash = end - timedelta(minutes=60)
    for i in range(4):
        ts = crash + timedelta(minutes=i * 2, seconds=rnd.randint(0, 20))
        ev(
            ts,
            "System",
            7034,
            2,
            "Service Control Manager",
            f"The Print Spooler service terminated unexpectedly.  It has done this {i + 1} time(s).",
            {"param1": "Print Spooler", "param2": str(i + 1)},
        )
        ev(
            ts + timedelta(seconds=1),
            "Application",
            1000,
            2,
            "Application Error",
            "Faulting application name: spoolsv.exe, version: 10.0.17763.5830",
            {"param1": "spoolsv.exe", "param7": "0xc0000005"},
        )

    ts = end - timedelta(minutes=300)
    ev(
        ts,
        "System",
        6008,
        2,
        "EventLog",
        "The previous system shutdown at 03:12:44 on 28/10/2026 was unexpected.",
        {"param1": "03:12:44", "param2": "28/10/2026"},
    )

    t = end - timedelta(days=8) + timedelta(minutes=20)
    while t < end:
        ev(
            t,
            "Application",
            1026,
            2,
            ".NET Runtime",
            "Application: InventorySync.exe Framework Version: v4.0.30319 Description: The process "
            "was terminated due to an unhandled exception.",
            {},
        )
        # cada ~1-2 h en el período reciente, más espaciado en la línea base
        t += timedelta(minutes=rnd.randint(50, 110) if t >= start else rnd.randint(300, 900))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", default="samples", type=Path)
    parser.add_argument("--seed", default=42, type=int)
    parser.add_argument("--hours", default=6, type=int, help="horas de actividad reciente")
    args = parser.parse_args()

    rnd = random.Random(args.seed)
    end = datetime.now(UTC).replace(second=0, microsecond=0)
    tl = Timeline()
    gen_web01(tl, args.out, end, args.hours, rnd)
    gen_db01(tl, args.out, end, args.hours, rnd)
    gen_dc01(tl, args.out, end, args.hours, rnd)
    for path, count in sorted(tl.write().items()):
        print(f"{count:>6} líneas  {path.as_posix()}")
    print(f"Datos generados hasta {end:%Y-%m-%d %H:%M} UTC")


if __name__ == "__main__":
    main()

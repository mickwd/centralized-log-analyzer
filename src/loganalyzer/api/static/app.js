// Dashboard: consume la API REST y dibuja con Chart.js. Sin build ni frameworks.
const PALETTE = ["#4ea1ff", "#ef7d3c", "#6cc070", "#c678dd", "#e6b54a", "#56b6c2", "#e5484d"];
let errorsChart = null;

const $ = (sel) => document.querySelector(sel);
const hours = () => $("#range").value;

function esc(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function fmtDate(iso) {
  return iso ? iso.replace("T", " ").slice(0, 19) : "";
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

async function loadKpis() {
  const s = await api(`/api/stats/summary?hours=${hours()}`);
  const errors = (s.by_severity.error || 0) + (s.by_severity.critical || 0);
  const authFail = s.by_category.auth_failure || 0;
  const items = [
    ["Eventos", s.total_events],
    ["Errores", errors],
    ["Auth fallidas", authFail],
    ["Hosts", Object.keys(s.by_host).length],
    ["Incidentes abiertos", s.open_incidents],
  ];
  $("#kpis").innerHTML = items
    .map(([label, value]) => `<div class="kpi"><div class="value">${value}</div><div class="label">${label}</div></div>`)
    .join("");
}

async function loadErrorsChart() {
  const data = await api(`/api/stats/errors-per-hour?hours=${hours()}`);
  const labels = data.labels.map((l) => l.slice(5, 16).replace("T", " "));
  const datasets = data.series.map((s, i) => ({
    label: s.host,
    data: s.data,
    backgroundColor: PALETTE[i % PALETTE.length],
    stack: "errors",
  }));
  if (errorsChart) errorsChart.destroy();
  errorsChart = new Chart($("#errorsChart"), {
    type: "bar",
    data: { labels, datasets },
    options: {
      maintainAspectRatio: false,
      scales: {
        x: { stacked: true, ticks: { color: "#8b98a5" }, grid: { color: "#2a3540" } },
        y: { stacked: true, beginAtZero: true, ticks: { color: "#8b98a5" }, grid: { color: "#2a3540" } },
      },
      plugins: { legend: { labels: { color: "#dbe3ea" } } },
    },
  });
}

async function loadIncidents() {
  const rows = await api("/api/incidents?status=open&limit=50");
  const body = $("#incidents tbody");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="muted">Sin incidentes abiertos</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map(
      (r) => `<tr>
        <td><span class="badge ${esc(r.severity)}">${esc(r.severity)}</span></td>
        <td>${esc(r.title)}<div class="muted">${esc(r.rule_id)}</div></td>
        <td>${esc(r.host || "-")}</td>
        <td class="num">${r.count}</td>
        <td>${fmtDate(r.last_seen)}</td>
        <td><button type="button" data-ack="${r.id}">Ack</button></td>
      </tr>`
    )
    .join("");
}

async function loadSignatures() {
  const rows = await api(`/api/stats/top-signatures?hours=${hours()}&limit=10`);
  $("#signatures tbody").innerHTML = rows.length
    ? rows
        .map((r) => `<tr><td class="num">${r.count}</td><td class="mono">${esc(r.template)}</td><td>${esc(r.hosts)}</td></tr>`)
        .join("")
    : '<tr><td colspan="3" class="muted">Sin errores en el rango</td></tr>';
}

async function loadIps() {
  const rows = await api(`/api/stats/top-ips?hours=${hours()}&limit=10`);
  $("#ips tbody").innerHTML = rows.length
    ? rows
        .map(
          (r) => `<tr><td class="mono">${esc(r.src_ip)}</td><td class="num">${r.auth_failures}</td>
            <td class="num">${r.http_errors}</td><td>${esc(r.hosts)}</td></tr>`
        )
        .join("")
    : '<tr><td colspan="4" class="muted">Sin datos</td></tr>';
}

async function loadMeta() {
  const meta = await api("/api/meta");
  const fill = (name, values) => {
    const select = document.querySelector(`#search [name=${name}]`);
    values.forEach((v) => select.insertAdjacentHTML("beforeend", `<option>${esc(v)}</option>`));
  };
  fill("host", meta.hosts);
  fill("category", meta.categories);
  fill("min_severity", meta.severities);
}

async function runSearch(event) {
  if (event) event.preventDefault();
  const params = new URLSearchParams();
  new FormData($("#search")).forEach((value, key) => {
    if (value) params.append(key, value);
  });
  params.set("limit", "50");
  const data = await api(`/api/events?${params}`);
  $("#searchTotal").textContent = `${data.total} eventos (mostrando ${data.items.length})`;
  $("#events tbody").innerHTML = data.items
    .map(
      (e) => `<tr><td>${fmtDate(e.timestamp)}</td><td>${esc(e.host)}</td>
        <td><span class="badge ${esc(e.severity)}">${esc(e.severity)}</span></td>
        <td>${esc(e.category)}</td><td class="mono">${esc(e.message)}</td></tr>`
    )
    .join("");
}

async function refresh() {
  try {
    await Promise.all([loadKpis(), loadErrorsChart(), loadIncidents(), loadSignatures(), loadIps()]);
    $("#updated").textContent = `actualizado ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    $("#updated").textContent = `error: ${err.message}`;
  }
}

document.addEventListener("click", async (ev) => {
  const id = ev.target.dataset.ack;
  if (!id) return;
  const by = prompt("Responsable del ack:", "soporte-l2");
  if (!by) return;
  await api(`/api/incidents/${id}/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ by }),
  });
  refresh();
});

$("#refresh").addEventListener("click", refresh);
$("#range").addEventListener("change", refresh);
$("#search").addEventListener("submit", runSearch);

loadMeta().then(() => runSearch());
refresh();
setInterval(refresh, 60000);

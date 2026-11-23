"use strict";

// Tiny DOM helper: h("p", {class: "x"}, "text", child). Never uses innerHTML.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "style") Object.assign(el.style, v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) el.append(c);
  return el;
}

const pct = (x, d = 2) => (x == null ? "n/a" : `${(x * 100).toFixed(d)}%`);
const ago = (ts) => {
  const m = Math.round((Date.now() / 1000 - ts) / 60);
  return m < 60 ? `${m} min ago` : `${Math.round(m / 60)} h ago`;
};
const utc = (ts) => new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";

function budget(label, objective, left) {
  const width = Math.max(0, Math.min(1, left ?? 0)) * 100;
  const cls = left == null ? "" : left < 0 ? "out" : left < 0.25 ? "low" : "";
  return h("div", { class: "budget" },
    h("div", { class: "label" }, label, " ", h("span", { class: "num" }, pct(objective, 1))),
    h("div", { class: `bar ${cls}`, role: "img", "aria-label": `${pct(left, 0)} of error budget left` },
      h("i", { style: { width: `${width}%` } })),
    h("div", {}, h("span", { class: "num" }, left == null ? "no data" : left < 0 ? "budget exhausted" : `${pct(left, 0)} budget left`)));
}

function days(daily) {
  return h("div", { class: "days", role: "img", "aria-label": "Daily SLI for the last 30 days" },
    daily.map((d) => {
      const cls = d.sli == null ? "none" : d.sli < 1 ? "bad" : "";
      const height = d.sli == null ? 10 : Math.max(10, 100 - (1 - d.sli) * 2000);
      return h("i", { class: cls, title: `${d.day}: ${pct(d.sli)}`, style: { height: `${height}%` } });
    }));
}

function alertTable(alerts) {
  return h("table", {},
    h("thead", {}, h("tr", {}, ["Rule", "Windows", "Burn (long / short)", "Threshold", "State"].map((t) => h("th", {}, t)))),
    h("tbody", {}, alerts.map((a) => h("tr", {},
      h("td", {}, `${a.rule} (${a.severity})`),
      h("td", { class: "num" }, `${a.long_window_h}h / ${a.short_window_h}h`),
      h("td", { class: "num" }, `${a.long_burn}x / ${a.short_burn}x`),
      h("td", { class: "num" }, `${a.factor}x`),
      h("td", {}, a.firing ? "firing" : "ok")))));
}

function card(t) {
  const up = !t.down && t.last.good;
  return h("article", { class: "card" },
    h("div", { class: "card-head" },
      h("h3", {}, t.name),
      h("a", { href: t.url }, t.url.replace("https://", "")),
      h("span", { class: `state ${up ? "up" : "down"}` }, t.down ? "down" : up ? "up" : "degraded")),
    h("div", { class: "stats" },
      h("div", { class: "stat" }, h("span", {}, "SLI, 30 days"), h("strong", {}, pct(t.sli, 3))),
      h("div", { class: "stat" }, h("span", {}, "Last probe"), h("strong", {}, `${t.last.status || "—"} · ${t.last.ms} ms`)),
      h("div", { class: "stat" }, h("span", {}, "p95 latency, 24h"), h("strong", {}, t.p95_ms_24h == null ? "n/a" : `${t.p95_ms_24h} ms`)),
      h("div", { class: "stat" }, h("span", {}, "Latency threshold"), h("strong", {}, `${t.latency_ms} ms`))),
    h("div", { class: "budgets" },
      budget("Internal SLO", t.slo, t.slo_budget_left),
      budget("Public SLA", t.sla, t.sla_budget_left)),
    days(t.daily),
    h("div", { class: "caption" }, h("span", {}, "30 days ago"), h("span", {}, "today")),
    h("details", {}, h("summary", {}, "Burn-rate alerts"), h("div", { class: "scroll" }, alertTable(t.alerts))));
}

function security(targets) {
  return h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Target"), h("th", { class: "num" }, "TLS expires in"), h("th", {}, "Headers"))),
    h("tbody", {}, targets.map((t) => {
      const d = t.security.tls_days_left;
      return h("tr", {},
        h("td", {}, t.name),
        h("td", { class: "num" }, d == null ? "unknown" : `${Math.floor(d)} days${t.security.tls_ok ? "" : " (renew!)"}`),
        h("td", {}, h("div", { class: "chips" }, t.security.headers.map((c) =>
          h("span", { class: `chip ${c.state}`, title: c.state }, `${c.header}: ${c.state}`)))));
    })));
}

const sum = (o) => Object.values(o || {}).reduce((a, b) => a + b, 0);
const sev = (o) => (o && sum(o) ? Object.entries(o).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(", ") : "0");

function scan(data) {
  if (!data) return h("p", { class: "muted" }, "No scan yet: the weekly workflow has not run.");
  return h("div", {},
    h("p", { class: "meta" }, `Last scan ${utc(data.generated_at)}. Counts only; details stay in the workflow logs.`),
    h("table", {},
      h("thead", {}, h("tr", {}, ["Repository", "Dependency CVEs", "Secrets", "Misconfig", "Semgrep"].map((x) => h("th", {}, x)))),
      h("tbody", {}, data.repos.map((r) => h("tr", {},
        h("td", {}, h("a", { href: `https://github.com/ogatalars/${r.repo}` }, r.repo)),
        h("td", {}, r.trivy ? sev(r.trivy.vulnerabilities) : "not scanned"),
        h("td", {}, r.trivy ? sev(r.trivy.secrets) : "not scanned"),
        h("td", {}, r.trivy ? sev(r.trivy.misconfigurations) : "not scanned"),
        h("td", {}, r.semgrep ? sev(r.semgrep) : "not scanned"))))));
}

function coverage(s) {
  return h("table", {},
    h("thead", {}, h("tr", {}, ["Target", "Probes received", "Expected", "Coverage", "Largest gap"].map((x) => h("th", {}, x)))),
    h("tbody", {}, s.targets.map((t) => h("tr", {},
      h("td", {}, t.name),
      h("td", { class: "num" }, String(t.coverage.observed)),
      h("td", { class: "num" }, String(t.coverage.expected)),
      h("td", { class: "num" }, pct(t.coverage.ratio, 1)),
      h("td", { class: "num" }, `${t.coverage.max_gap_min} min`)))));
}

async function getJSON(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

(async () => {
  const updated = document.getElementById("updated");
  try {
    const status = await getJSON("data/status.json");
    const sec = await getJSON("data/security.json").catch(() => null);
    updated.textContent = `Last probe round ${utc(status.generated_at)} (${ago(status.generated_at)}), every ~${status.interval_minutes} min, ${status.window_days}-day window.`;
    document.getElementById("targets").append(...status.targets.map(card));
    document.getElementById("security").append(h("div", { class: "scroll" }, security(status.targets)));
    document.getElementById("scan").append(scan(sec));
    document.getElementById("coverage").append(coverage(status));
  } catch (e) {
    updated.textContent = `Could not load data (${e.message}).`;
  }
})();

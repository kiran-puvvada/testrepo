/* ThreatPulse - threat intelligence dashboard (vanilla JS, no build step) */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => (n ?? 0).toLocaleString();
const VIEW = () => $("#view");

const S = {
  meta: null,
  filters: { period: "90d", industry: "", region: "", attack: "", q: "", year: "", month: "", day: "", from: "", to: "" },
  gran: null,
  lastSync: new Date().toISOString().slice(0, 19) + "Z",
  route: "overview",
};
const PATTERN = {}; // key -> {name, icon, color}

// ------------------------------------------------------------------ API
async function api(path, params = {}, opts = {}) {
  const u = new URL(path, location.origin);
  Object.entries(params).forEach(([k, v]) => { if (v !== "" && v != null) u.searchParams.set(k, v); });
  const r = await fetch(u, opts);
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.headers.get("content-type")?.includes("json") ? r.json() : r.text();
}

// ------------------------------------------------------------------ time filters
function isoDay(d) { return d.toISOString().slice(0, 10); }
function range() {
  const f = S.filters, now = new Date();
  const back = (days) => isoDay(new Date(now - days * 864e5));
  switch (f.period) {
    case "1d": return { from: new Date(now - 864e5).toISOString().slice(0, 19) + "Z", to: "" };
    case "7d": return { from: back(7), to: "" };
    case "30d": return { from: back(30), to: "" };
    case "90d": return { from: back(90), to: "" };
    case "365d": return { from: back(365), to: "" };
    case "year": return f.year ? { from: `${f.year}-01-01`, to: `${f.year}-12-31` } : {};
    case "month": if (f.month) { const [y, m] = f.month.split("-").map(Number); return { from: `${f.month}-01`, to: isoDay(new Date(Date.UTC(y, m, 0))) }; } return {};
    case "day": return f.day ? { from: f.day, to: f.day } : {};
    case "custom": return { from: f.from, to: f.to };
    default: return {};
  }
}
function autoGran() {
  const p = S.filters.period;
  if (p === "1d" || p === "day") return "hour";
  if (p === "365d" || p === "year" || p === "all") return "month";
  return "day";
}
function params(extra = {}) {
  const f = S.filters;
  return { ...range(), industry: f.industry, region: f.region, attack: f.attack, q: f.q, ...extra };
}
function periodLabel() {
  const f = S.filters, o = $("#f-period").selectedOptions[0];
  if (f.period === "year") return f.year || "year";
  if (f.period === "month") return f.month || "month";
  if (f.period === "day") return f.day || "day";
  if (f.period === "custom") return `${f.from || "…"} → ${f.to || "…"}`;
  return o ? o.textContent.toLowerCase() : "";
}
function filterSummary() {
  const f = S.filters, bits = [periodLabel()];
  if (f.industry) bits.push(f.industry);
  if (f.region) bits.push(f.region);
  if (f.attack) bits.push(PATTERN[f.attack]?.name || f.attack);
  if (f.q) bits.push(`“${f.q}”`);
  return bits.join(" · ");
}

// ------------------------------------------------------------------ helpers
function ago(iso) {
  if (!iso) return "";
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago`;
  return iso.slice(0, 10);
}
const sevPill = (s) => `<span class="pill sev sev-${esc(s || "unknown")}">${esc(s || "n/a")}</span>`;
const kevPill = () => `<span class="pill kev" title="CISA Known Exploited Vulnerability">KEV</span>`;
function patPill(k, click = true) {
  const p = PATTERN[k]; if (!p) return "";
  return `<span class="pill ${click ? "click" : ""}" ${click ? `data-attack="${esc(k)}"` : ""}><span>${p.icon}</span>${esc(p.name)}</span>`;
}
const tagPill = (t, kind) => `<span class="pill click" data-${kind}="${esc(t)}">${esc(t)}</span>`;
function cvssBadge(v) {
  if (v == null || v < 0) return `<span class="muted">–</span>`;
  const s = v >= 9 ? "critical" : v >= 7 ? "high" : v >= 4 ? "medium" : "low";
  return `<span class="pill sev sev-${s}">${Number(v).toFixed(1)}</span>`;
}
function epssBar(v) {
  if (v == null) return `<span class="muted">–</span>`;
  const pct = v * 100;
  return `<span class="tabular" title="EPSS: probability of exploitation in next 30 days">${pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%</span>`;
}
function copy(text, btn) {
  const done = () => { if (btn) { const o = btn.textContent; btn.textContent = "✓ Copied"; setTimeout(() => (btn.textContent = o), 1400); } };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select();
  try { document.execCommand("copy"); } catch (e) { /* ignore */ } t.remove(); done();
}
function download(name, text, type = "text/plain") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function pivots(i) {
  const v = encodeURIComponent(i.value), L = [];
  if (i.type === "ip") L.push(["VT", `https://www.virustotal.com/gui/ip-address/${v}`], ["Shodan", `https://www.shodan.io/host/${v}`], ["AbuseIPDB", `https://www.abuseipdb.com/check/${v}`], ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${v}`]);
  else if (i.type === "domain") L.push(["VT", `https://www.virustotal.com/gui/domain/${v}`], ["urlscan", `https://urlscan.io/search/#domain:${v}`], ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${v}`]);
  else if (i.type === "url") L.push(["VT", `https://www.virustotal.com/gui/search/${v}`], ["urlscan", `https://urlscan.io/search/#${v}`], ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${v}`]);
  else L.push(["VT", `https://www.virustotal.com/gui/file/${v}`], ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=sha256%3A${v}`]);
  L.push(["CyberChef", `https://gchq.github.io/CyberChef/#input=${btoa(unescape(encodeURIComponent(i.value)))}`]);
  return `<span class="pivots">${L.map(([n, u]) => `<a href="${u}" target="_blank" rel="noopener">${n}</a>`).join("")}</span>`;
}
function loading(n = 6) { return `<div class="card">${Array.from({ length: n }, () => '<div class="skeleton"></div>').join("")}</div>`; }
function head(title, sub, right = "") {
  return `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div><div class="tags no-print">${right}</div></div>`;
}

// ------------------------------------------------------------------ tooltip
const TT = {
  el: null,
  show(html, x, y) {
    const t = this.el; t.innerHTML = html; t.classList.add("on");
    const w = t.offsetWidth, h = t.offsetHeight;
    let left = x + 14, top = y + 14;
    if (left + w > innerWidth - 8) left = x - w - 14;
    if (top + h > innerHeight - 8) top = y - h - 14;
    t.style.left = left + "px"; t.style.top = top + "px";
  },
  hide() { this.el.classList.remove("on"); },
};

// ------------------------------------------------------------------ charts (SVG)
function niceMax(v) {
  if (v <= 0) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}
function fmtBucket(b, gran) {
  if (!b) return "";
  if (gran === "year") return b;
  if (gran === "month") { const [y, m] = b.split("-"); return new Date(Date.UTC(+y, +m - 1, 1)).toLocaleString(undefined, { month: "short", year: "2-digit", timeZone: "UTC" }); }
  if (gran === "hour") return b.slice(5, 10) + " " + b.slice(11, 13) + ":00";
  return new Date(b + "T00:00:00Z").toLocaleString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}
/** Line/area chart. series: [{name, color, values}] (max 2 shown) */
function lineChart(el, labels, series, { gran = "day", height = 220, area = true, onClick } = {}) {
  const W = Math.max(el.clientWidth || 600, 280), H = height, m = { l: 36, r: 12, t: 12, b: 26 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  if (!labels.length) { el.innerHTML = `<div class="empty">No data in this time range</div>`; return; }
  const max = niceMax(Math.max(1, ...series.flatMap((s) => s.values)));
  const x = (i) => m.l + (labels.length === 1 ? iw / 2 : (i * iw) / (labels.length - 1));
  const y = (v) => m.t + ih - (v / max) * ih;
  let g = "";
  for (let k = 0; k <= 4; k++) {
    const v = (max / 4) * k, yy = y(v);
    g += `<line class="${k ? "gridline" : "baseline"}" x1="${m.l}" x2="${W - m.r}" y1="${yy}" y2="${yy}"/>`;
    g += `<text class="axis-label" x="${m.l - 6}" y="${yy + 4}" text-anchor="end">${v % 1 ? v.toFixed(1) : fmt(v)}</text>`;
  }
  const ticks = Math.min(labels.length, Math.max(2, Math.floor(iw / 80)));
  for (let k = 0; k < ticks; k++) {
    const i = Math.round((k * (labels.length - 1)) / Math.max(1, ticks - 1));
    g += `<text class="axis-label" x="${x(i)}" y="${H - 6}" text-anchor="${k === 0 ? "start" : k === ticks - 1 ? "end" : "middle"}">${esc(fmtBucket(labels[i], gran))}</text>`;
  }
  const paths = series.map((s, si) => {
    const pts = s.values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
    const line = `<polyline fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="${pts.join(" ")}"/>`;
    const fill = area && si === 0 ? `<polygon fill="${s.color}" opacity=".12" points="${x(0)},${y(0)} ${pts.join(" ")} ${x(labels.length - 1)},${y(0)}"/>` : "";
    return fill + line;
  }).join("");
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="${esc(series.map((s) => s.name).join(", "))} over time">
    ${g}${paths}<line class="crosshair" id="ch" y1="${m.t}" y2="${m.t + ih}" x1="-10" x2="-10"/>
    <g id="dots">${series.map((s) => `<circle r="4.5" fill="${s.color}" stroke="var(--surface-1)" stroke-width="2" cx="-10" cy="-10"/>`).join("")}</g>
    <rect x="${m.l}" y="${m.t}" width="${iw}" height="${ih}" fill="transparent" style="cursor:${onClick ? "pointer" : "crosshair"}"/></svg>`;
  const svg = $("svg", el), rect = $("rect", svg), ch = $("#ch", svg), dots = $$("#dots circle", svg);
  const idxAt = (ev) => {
    const b = svg.getBoundingClientRect(), px = ((ev.clientX - b.left) / b.width) * W;
    return Math.max(0, Math.min(labels.length - 1, Math.round(((px - m.l) / iw) * (labels.length - 1))));
  };
  rect.addEventListener("mousemove", (ev) => {
    const i = idxAt(ev);
    ch.setAttribute("x1", x(i)); ch.setAttribute("x2", x(i));
    dots.forEach((d, si) => { d.setAttribute("cx", x(i)); d.setAttribute("cy", y(series[si].values[i])); });
    TT.show(`<div class="tt-title">${esc(fmtBucket(labels[i], gran))}</div>` + series.map((s) =>
      `<div class="tt-row"><span><span class="dot" style="background:${s.color}"></span> ${esc(s.name)}</span><b class="tabular">${fmt(s.values[i])}</b></div>`).join(""), ev.clientX, ev.clientY);
  });
  rect.addEventListener("mouseleave", () => { TT.hide(); ch.setAttribute("x1", -10); ch.setAttribute("x2", -10); dots.forEach((d) => d.setAttribute("cx", -10)); });
  if (onClick) rect.addEventListener("click", (ev) => onClick(labels[idxAt(ev)]));
}
function sparkline(values, color = "var(--series-1)", w = 120, h = 30) {
  if (!values?.length) return "";
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(values.length === 1 ? w / 2 : (i * w) / (values.length - 1)).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true"><polyline fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="${pts}"/></svg>`;
}
/** Horizontal bar list - identity by label, single hue */
function barList(items, { key = "name", onClick, label = (i) => i.name, limit = 10, unit = "reports" } = {}) {
  if (!items?.length) return `<div class="empty">No data</div>`;
  const max = Math.max(...items.map((i) => i.count));
  return `<div class="barlist">${items.slice(0, limit).map((i) => `
    <div class="bl-row" data-k="${esc(i[key])}" data-tt="${esc(label(i))}: ${fmt(i.count)} ${unit}" ${onClick ? "" : 'style="cursor:default"'}>
      <span class="bl-name">${label(i)}</span>
      <span class="bl-track"><span class="bl-fill" style="display:block;width:${(i.count / max) * 100}%"></span></span>
      <span class="bl-val">${fmt(i.count)}</span></div>`).join("")}</div>`;
}
function wireBars(root, onClick) {
  $$(".bl-row", root).forEach((r) => {
    r.addEventListener("mousemove", (e) => TT.show(esc(r.dataset.tt), e.clientX, e.clientY));
    r.addEventListener("mouseleave", () => TT.hide());
    if (onClick) r.addEventListener("click", () => { TT.hide(); onClick(r.dataset.k); });
  });
}
/** Severity donut - status colors, always with labels */
function donut(sev) {
  const order = [["critical", "var(--critical)", "▲"], ["high", "var(--serious)", "◆"], ["medium", "var(--warning)", "●"], ["low", "var(--low)", "○"]];
  const total = order.reduce((a, [k]) => a + (sev[k] || 0), 0);
  if (!total) return `<div class="empty">No data</div>`;
  const R = 52, C = 2 * Math.PI * R; let off = 0;
  const arcs = order.map(([k, c]) => {
    const v = sev[k] || 0, len = (v / total) * C; const gap = v && len > 4 ? 2 : 0;
    const s = `<circle class="dn" data-tt="${k}: ${fmt(v)} (${((v / total) * 100).toFixed(0)}%)" r="${R}" cx="70" cy="70" fill="none" stroke="${c}" stroke-width="18"
      stroke-dasharray="${Math.max(0, len - gap)} ${C}" stroke-dashoffset="${-off}" transform="rotate(-90 70 70)"/>`;
    off += len; return s;
  }).join("");
  return `<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">
    <svg viewBox="0 0 140 140" width="140" height="140" role="img" aria-label="Severity distribution">${arcs}
      <text x="70" y="68" text-anchor="middle" style="font-size:22px;font-weight:700;fill:var(--text-primary)">${fmt(total)}</text>
      <text x="70" y="86" text-anchor="middle" style="font-size:11px;fill:var(--muted)">articles</text></svg>
    <div style="display:flex;flex-direction:column;gap:6px">${order.map(([k, c, ic]) => `<div class="tags" style="align-items:center"><span style="color:${c}">${ic}</span>
      <span style="min-width:62px;text-transform:capitalize">${k}</span><b class="tabular">${fmt(sev[k] || 0)}</b></div>`).join("")}</div></div>`;
}
function wireDonut(root) {
  $$(".dn", root).forEach((c) => {
    c.addEventListener("mousemove", (e) => TT.show(esc(c.dataset.tt), e.clientX, e.clientY));
    c.addEventListener("mouseleave", () => TT.hide());
  });
}

// ------------------------------------------------------------------ global click delegation for tag pills
document.addEventListener("click", (e) => {
  const p = e.target.closest("[data-attack],[data-industry],[data-region],[data-actor],[data-cve]");
  if (!p || p.closest(".bl-row")) return;
  if (p.dataset.cve) { location.hash = `#/report/cve-${p.dataset.cve}`; return; }
  if (p.dataset.actor) { setFilter("q", p.dataset.actor); location.hash = "#/feed"; return; }
  const k = p.dataset.attack ? "attack" : p.dataset.industry ? "industry" : "region";
  setFilter(k, p.dataset[k]);
});
function setFilter(k, v) {
  S.filters[k] = v;
  if (k === "q") $("#q").value = v; else { const el = $(`#f-${k}`); if (el) el.value = v; }
  saveFilters(); render();
}

// ================================================================== VIEWS
const VIEWS = {};

// ------------------------------------------------------------------ Overview
VIEWS.overview = async () => {
  VIEW().innerHTML = head("Threat Overview", `Global threat landscape · ${esc(filterSummary())}`) + loading(8);
  const gran = S.gran || autoGran();
  const seq = renderSeq;
  const [st, upd] = await Promise.all([api("/api/stats", params({ granularity: gran })), api("/api/articles", params({ limit: 20 }))]);
  if (seq !== renderSeq) return;
  const k = st.kpis;
  const kpi = (label, val, note, route, ico) => `<div class="card kpi ${route ? "link" : ""}" ${route ? `data-go="${route}"` : ""}>
     <div class="k-label">${ico} ${label}</div><div class="k-val">${fmt(val)}</div><div class="k-note">${note}</div></div>`;
  const ticker = upd.items.slice(0, 14).map((a) => `<a href="${esc(a.url)}" target="_blank" rel="noopener"><span class="src">${esc(a.source)}</span>${esc(a.title)}</a>`).join("");
  const byAttack = st.timeline.by_attack;
  VIEW().innerHTML = head("Threat Overview", `Global threat landscape · ${esc(filterSummary())}`,
      `<div class="seg-toggle" id="gran">${["hour", "day", "month", "year"].map((g) => `<button data-g="${g}" class="${g === gran ? "on" : ""}">${g[0].toUpperCase() + g.slice(1)}</button>`).join("")}</div>`) +
    (ticker ? `<div class="ticker"><span class="ticker-label">● LIVE</span><div class="ticker-track"><div class="ticker-inner">${ticker}${ticker}</div></div></div>` : "") +
    `<div class="grid g-kpi">
      ${kpi("News & research", k.articles, "articles in range", "feed", "📰")}
      ${kpi("Critical alerts", k.critical, "zero-days, KEV, active exploitation", "feed?severity=critical", "🚨")}
      ${kpi("Known exploited", k.kev, "CISA KEV additions in range", "vulns?kev=1", "🔥")}
      ${kpi("CVEs tracked", k.cves, "published in range", "vulns", "🐞")}
      ${kpi("IOCs", k.iocs, "first seen in range", "iocs", "🧬")}
      ${kpi("Threat reports", k.reports, "auto-generated", "reports", "📑")}
      ${kpi("Threat actors", k.actors, "named in coverage", null, "🎯")}
      ${kpi("Live sources", k.sources, "healthy feeds", "sources", "📡")}
    </div>
    <div class="grid g-21 mt">
      <div class="card"><div class="card-head"><div><h3>Threat activity over time</h3><div class="sub">News & research volume per ${gran} — click a point to drill into that ${gran}</div></div></div>
        <div class="chart" id="c-timeline"></div></div>
      <div class="card"><h3>Severity mix</h3><div class="sub">Articles by assessed severity</div><div id="c-sev">${donut(st.severity)}</div></div>
    </div>
    <div class="card mt"><div class="card-head"><div><h3>Trending attack patterns</h3><div class="sub">Volume and trajectory per pattern — click to filter the whole dashboard</div></div>
      <a href="#/patterns" class="btn sm">Playbooks →</a></div>
      <div class="grid g-cards" style="grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px">
      ${st.attack_types.slice(0, 12).map((a) => `<div class="card pattern-card" data-attack="${a.key}" style="padding:12px 14px;box-shadow:none">
         <div style="display:flex;justify-content:space-between;align-items:center"><span class="pattern-icon" style="width:34px;height:34px;font-size:18px">${a.icon}</span>
         ${byAttack[a.key] ? sparkline(byAttack[a.key]) : ""}</div>
         <div style="margin-top:8px;font-weight:620;font-size:13.5px">${esc(a.name)}</div>
         <div class="pattern-count">${fmt(a.count)}</div></div>`).join("") || '<div class="empty">No data</div>'}
      </div></div>
    <div class="grid g-3 mt">
      <div class="card"><h3>Targeted industries</h3><div class="sub">Click to filter</div><div id="b-ind">${barList(st.industries, { onClick: 1 })}</div></div>
      <div class="card"><h3>Targeted regions</h3><div class="sub">Click to filter</div><div id="b-reg">${barList(st.regions, { onClick: 1 })}</div></div>
      <div class="card"><h3>Active threat actors</h3><div class="sub">Most referenced groups</div><div id="b-act">${barList(st.actors, { onClick: 1, unit: "mentions" })}</div></div>
    </div>
    <div class="grid g-2 mt">
      <div class="card"><div class="card-head"><div><h3>Trending vulnerabilities</h3><div class="sub">Most discussed CVEs in coverage</div></div><a class="btn sm" href="#/vulns">All CVEs →</a></div>
        ${cveMiniTable(st.trending_cves, true)}</div>
      <div class="card"><div class="card-head"><div><h3>Latest CISA KEV additions</h3><div class="sub">Confirmed in-the-wild exploitation</div></div><a class="btn sm" href="#/vulns?kev=1">KEV →</a></div>
        ${cveMiniTable(st.latest_kev, false)}</div>
    </div>
    <div class="grid g-2 mt">
      <div class="card"><div class="card-head"><div><h3>Top threat reports</h3><div class="sub">Highest-scoring correlated reports</div></div><a class="btn sm" href="#/reports">All reports →</a></div>
        ${st.top_reports.map((r) => `<div class="feed-item" style="cursor:pointer" data-go="report/${esc(r.rid)}"><div class="feed-bar" style="background:var(--${sevVar(r.severity)})"></div>
          <div><div class="feed-title" style="font-size:14px">${esc(r.title)}</div><div class="feed-meta">${sevPill(r.severity)} <span>${esc(kindLabel(r.kind))}</span><span>updated ${ago(r.updated)}</span></div></div></div>`).join("") || '<div class="empty">No reports yet</div>'}</div>
      <div class="card"><h3>Malware families & IOC types</h3><div class="sub">From abuse.ch, OTX and article extraction</div>
        <div id="b-mal">${barList(st.malware, { onClick: 1, unit: "IOCs" })}</div>
        <div class="tags mt">${st.ioc_types.map((t) => `<span class="pill">${esc(t.name)} · ${fmt(t.count)}</span>`).join("")}</div></div>
    </div>
    <div class="card mt"><div class="card-head"><div><h3>Latest headlines</h3><div class="sub">Newest items for the current filters</div></div><a class="btn sm" href="#/feed">Open feed →</a></div>
      ${upd.items.slice(0, 8).map(feedItem).join("") || '<div class="empty">No articles</div>'}</div>`;

  lineChart($("#c-timeline"), st.timeline.labels, [{ name: "Articles", color: "var(--series-1)", values: st.timeline.articles }],
    { gran, onClick: (b) => drill(b, gran) });
  wireDonut($("#c-sev"));
  wireBars($("#b-ind"), (v) => setFilter("industry", v));
  wireBars($("#b-reg"), (v) => setFilter("region", v));
  wireBars($("#b-act"), (v) => { setFilter("q", v); location.hash = "#/feed"; });
  wireBars($("#b-mal"), (v) => { location.hash = `#/iocs?malware=${encodeURIComponent(v)}`; });
  $$("#gran button").forEach((b) => b.addEventListener("click", () => { S.gran = b.dataset.g; render(); }));
  wireFeed(VIEW());
};
function drill(bucket, gran) {
  const f = S.filters;
  if (gran === "year") { f.period = "year"; f.year = bucket; }
  else if (gran === "month") { f.period = "month"; f.month = bucket; }
  else if (gran === "day") { f.period = "day"; f.day = bucket; }
  else return;
  S.gran = null; syncFilterUI(); saveFilters(); render();
}
const sevVar = (s) => ({ critical: "critical", high: "serious", medium: "warning" }[s] || "low");
const kindLabel = (k) => ({ cve: "Vulnerability report", malware: "Malware campaign", actor: "Threat actor", trend: "Attack trend" }[k] || k);
function cveMiniTable(rows, mentions) {
  if (!rows?.length) return `<div class="empty">No CVEs</div>`;
  return `<div class="table-wrap"><table class="t"><thead><tr><th>CVE</th><th>Product</th><th>CVSS</th><th>EPSS</th>${mentions ? "<th>Mentions</th>" : "<th>Added</th>"}</tr></thead><tbody>
  ${rows.map((c) => `<tr class="click" data-go="report/cve-${esc(c.cve_id)}"><td class="mono" style="white-space:nowrap">${esc(c.cve_id)} ${c.kev ? kevPill() : ""}</td>
    <td>${esc([c.vendor, c.product].filter(Boolean).join(" ") || "—")}${c.ransomware === "Known" ? ' <span class="pill" title="Known ransomware use">🔒 ransomware</span>' : ""}</td>
    <td>${cvssBadge(c.cvss)}</td><td>${epssBar(c.epss)}</td><td class="num">${mentions ? fmt(c.mentions) : esc((c.kev_added || "").slice(0, 10))}</td></tr>`).join("")}</tbody></table></div>`;
}

// ------------------------------------------------------------------ Feed
function feedItem(a) {
  const tags = [...(a.attack_types || []).map((t) => patPill(t)), ...(a.industries || []).slice(0, 2).map((t) => tagPill(t, "industry")),
    ...(a.regions || []).slice(0, 2).map((t) => tagPill(t, "region")), ...(a.actors || []).slice(0, 3).map((t) => `<span class="pill click" data-actor="${esc(t)}">👤 ${esc(t)}</span>`),
    ...(a.cves || []).slice(0, 4).map((c) => `<span class="pill click mono" data-cve="${esc(c)}">${esc(c)}</span>`)].join("");
  const iocs = a.iocs || [];
  return `<div class="feed-item"><div class="feed-bar" style="background:var(--${sevVar(a.severity)})"></div><div>
    <a class="feed-title" href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.title)}</a>
    <div class="feed-meta">${sevPill(a.severity)}<b>${esc(a.source)}</b><span title="${esc(a.published)}">${ago(a.published)}</span>${iocs.length ? `<span>🧬 ${iocs.length} IOCs</span>` : ""}</div>
    <div class="feed-sum clamp2">${esc(a.summary)}</div>
    <div class="tags" style="margin-top:7px">${tags}</div>
    ${iocs.length ? `<details class="feed-more"><summary class="muted" style="cursor:pointer;font-size:12.5px">Show extracted IOCs</summary>
      <div class="table-wrap"><table class="t"><tbody>${iocs.slice(0, 30).map((i) => `<tr><td>${esc(i.type)}</td><td class="mono">${esc(i.value)}</td><td>${pivots(i)}</td></tr>`).join("")}</tbody></table></div>
      <button class="btn sm" data-hunt='${esc(JSON.stringify(iocs.map((i) => i.value)))}'>🔎 Build hunt queries</button></details>` : ""}
  </div></div>`;
}
function wireFeed(root) {
  $$("[data-hunt]", root).forEach((b) => b.addEventListener("click", () => {
    sessionStorage.setItem("hunt", JSON.parse(b.dataset.hunt).join("\n")); location.hash = "#/hunt";
  }));
}
VIEWS.feed = async (qp) => {
  let page = 1, sev = qp.get("severity") || "", src = qp.get("source") || "";
  const sources = S.meta.sources || [];
  VIEW().innerHTML = head("Live Threat Feed", `News, advisories & research from ${sources.length} sources · ${esc(filterSummary())}`,
    `<select class="ctl" id="feed-src"><option value="">All sources</option>${sources.map((s) => `<option ${s === src ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
     <select class="ctl" id="feed-sev"><option value="">Any severity</option>${["critical", "high", "medium", "low"].map((s) => `<option ${s === sev ? "selected" : ""}>${s}</option>`).join("")}</select>`) +
    `<div class="card"><div id="feed-total" class="sub"></div><div id="feed-list">${loading(5)}</div><div style="text-align:center" class="mt"><button class="btn" id="feed-more" hidden>Load more</button></div></div>`;
  const load = async (append) => {
    const d = await api("/api/articles", params({ page, limit: 30, severity: sev, source: src }));
    $("#feed-total").textContent = `${fmt(d.total)} articles`;
    const html = d.items.map(feedItem).join("") || '<div class="empty">No articles match these filters. Try “All time”.</div>';
    const list = $("#feed-list");
    if (append) list.insertAdjacentHTML("beforeend", html); else list.innerHTML = html;
    wireFeed(list);
    $("#feed-more").hidden = page * 30 >= d.total;
  };
  $("#feed-src").onchange = (e) => { src = e.target.value; page = 1; load(); };
  $("#feed-sev").onchange = (e) => { sev = e.target.value; page = 1; load(); };
  $("#feed-more").onclick = () => { page++; load(true); };
  await load();
};

// ------------------------------------------------------------------ Reports list
VIEWS.reports = async (qp) => {
  let kind = qp.get("kind") || "", sort = qp.get("sort") || "score", page = 1;
  VIEW().innerHTML = head("Threat Reports", "Correlated intelligence: attack chain, ATT&CK mapping, IOCs, CVEs, mitigations and SIEM hunt queries",
    `<div class="seg-toggle" id="r-kind">${[["", "All"], ["cve", "Vulnerabilities"], ["malware", "Malware"], ["actor", "Actors"], ["trend", "Trends"]].map(([k, l]) => `<button data-k="${k}" class="${k === kind ? "on" : ""}">${l}</button>`).join("")}</div>
     <select class="ctl" id="r-sort"><option value="score">Trending</option><option value="recent" ${sort === "recent" ? "selected" : ""}>Most recent</option></select>`) +
    `<div class="sub" id="r-total"></div><div class="grid g-cards" id="r-list">${loading(3)}</div><div style="text-align:center" class="mt"><button class="btn" id="r-more" hidden>Load more</button></div>`;
  const load = async (append) => {
    const d = await api("/api/reports", { ...params({ page, limit: 30 }), from: range().from, to: range().to, kind, sort });
    $("#r-total").textContent = `${fmt(d.total)} reports · ${filterSummary()}`;
    const html = d.items.map(reportCard).join("") || '<div class="empty card">No reports for these filters. Try “All time”.</div>';
    if (append) $("#r-list").insertAdjacentHTML("beforeend", html); else $("#r-list").innerHTML = html;
    $("#r-more").hidden = page * 30 >= d.total;
  };
  $$("#r-kind button").forEach((b) => b.onclick = () => { kind = b.dataset.k; $$("#r-kind button").forEach((x) => x.classList.toggle("on", x === b)); page = 1; load(); });
  $("#r-sort").onchange = (e) => { sort = e.target.value; page = 1; load(); };
  $("#r-more").onclick = () => { page++; load(true); };
  await load();
};
function reportCard(r) {
  const icon = { cve: "🐞", malware: "🦠", actor: "👤", trend: "📈" }[r.kind] || "📑";
  return `<div class="card pattern-card" data-go="report/${esc(r.rid)}">
    <div class="card-head"><div class="tags" style="align-items:center"><span class="pattern-icon" style="width:34px;height:34px;font-size:17px">${icon}</span>${sevPill(r.severity)}<span class="muted" style="font-size:12px">${esc(kindLabel(r.kind))}</span></div>
    <span class="muted" style="font-size:12px">${ago(r.updated)}</span></div>
    <div class="feed-title" style="font-size:14.5px;line-height:1.35">${esc(r.title)}</div>
    <div class="feed-sum clamp2" style="margin:6px 0 10px;font-size:13px">${esc(r.summary)}</div>
    <div class="tags">${(r.attack_types || []).slice(0, 2).map((t) => patPill(t, false)).join("")}${r.industries.map((t) => `<span class="pill">${esc(t)}</span>`).join("")}</div>
    <div class="feed-meta" style="margin-top:10px">🧬 ${fmt(r.n_iocs)} IOCs · 🐞 ${fmt(r.n_cves)} CVEs · 📰 ${fmt(r.n_articles)} sources</div></div>`;
}

// ------------------------------------------------------------------ Report detail
VIEWS.report = async (qp, rid) => {
  VIEW().innerHTML = loading(10);
  let r; const seq = renderSeq;
  try { r = await api(`/api/reports/${encodeURIComponent(rid)}`); if (seq !== renderSeq) return; }
  catch (e) { VIEW().innerHTML = `<div class="card empty">Report not found. <a href="#/reports">Back to reports</a></div>`; return; }
  const c = r.cve;
  const facts = [];
  if (c) {
    facts.push(["CVSS", c.cvss != null && c.cvss >= 0 ? `${c.cvss}` : "–", c.severity || ""]);
    facts.push(["EPSS", c.epss != null ? `${(c.epss * 100).toFixed(1)}%` : "–", c.epss_pct != null ? `percentile ${(c.epss_pct * 100).toFixed(0)}` : "exploit probability"]);
    facts.push(["CISA KEV", c.kev ? "Yes" : "No", c.kev ? `added ${c.kev_added}` : "not in catalog"]);
    if (c.kev_due) facts.push(["Patch due", c.kev_due, "federal deadline"]);
    facts.push(["Ransomware use", c.ransomware || "Unknown", "per CISA"]);
    facts.push(["Published", (c.published || "").slice(0, 10) || "–", ""]);
  }
  if (r.stats) facts.push(["Reports (window)", r.stats.current, `prev ${r.stats.previous}`], ["Change", `${r.stats.growth > 0 ? "+" : ""}${r.stats.growth}%`, "vs previous window"]);
  facts.push(["IOCs", (r.iocs || []).length, "indicators"], ["Related CVEs", (r.cves || []).length, ""], ["Sources", (r.articles || []).length, "articles"]);
  let sec = 0;
  const S_ = (title, id) => `<div class="section-title" id="${id}"><span class="num">${++sec}</span>${title}</div>`;
  const iocs = r.iocs || [];
  VIEW().innerHTML = `
    <div class="no-print" style="margin-bottom:10px"><a href="#/reports">← All reports</a></div>
    <div class="report-hero">
      <div class="tags" style="align-items:center">${sevPill(r.severity)}<span class="pill">${esc(kindLabel(r.kind))}</span>${c?.kev ? kevPill() : ""}
        ${(r.attack_types || []).map((t) => patPill(t, false)).join("")}
        <span class="muted" style="font-size:12px">Generated ${ago(r.generated || r.updated)}${r.created ? ` · first seen ${esc((r.created || "").slice(0, 10))}` : ""}</span></div>
      <h1>${esc(r.title)}</h1>
      <div class="summary">${esc(r.executive_summary)}</div>
      <div class="facts">${facts.map(([l, v, n]) => `<div class="fact"><div class="f-l">${l}</div><div class="f-v">${esc(v)}</div><div class="muted" style="font-size:11.5px">${esc(n)}</div></div>`).join("")}</div>
      <div class="toc no-print">
        <a class="pill click" href="#how">How the attack works</a><a class="pill click" href="#ttp">ATT&CK & defense</a>
        <a class="pill click" href="#queries">Hunt queries</a><a class="pill click" href="#iocs">IOCs</a>
        <a class="pill click" href="#targets">Targets</a><a class="pill click" href="#sources">Sources</a>
        <button class="btn sm" id="r-print">🖨 Print / PDF</button><button class="btn sm" id="r-md">⬇ Markdown</button><button class="btn sm" id="r-json">⬇ JSON</button>
      </div>
    </div>
    ${c?.description ? `${S_("Vulnerability details", "vuln")}<div class="card"><p style="margin:0 0 10px">${esc(c.description)}</p>
       <div class="tags">${c.vector ? `<span class="pill mono">${esc(c.vector)}</span>` : ""}${(r.cwe || []).map((w) => `<a class="pill click" target="_blank" rel="noopener" href="${w.url}">${esc(w.id)}</a>`).join("")}</div>
       ${c.required_action ? `<div class="notice mt"><b>Required action (CISA):</b> ${esc(c.required_action)}</div>` : ""}</div>` : ""}

    ${S_("How the attack works — step by step", "how")}
    <div class="sub">Typical attack flow for this threat, mapped to MITRE ATT&CK. Each stage shows what the attacker does, the techniques used, and D3FEND countermeasures.</div>
    <div class="chain">${(r.chain || []).map((s, i) => `<div class="stage"><div class="stage-n">Stage ${i + 1}</div><h4>${esc(s.stage)}</h4><p>${esc(s.description)}</p>
      <div>${s.techniques.map((t) => `<a class="tech" href="${esc(t.url)}" target="_blank" rel="noopener" title="${esc(t.name)}"><b>${esc(t.id)}</b>${esc(t.name)}</a>`).join("")}</div>
      ${s.defend?.length ? `<div class="defend">🛡 ${s.defend.map((d) => esc(d)).join(" · ")}</div>` : ""}</div>`).join("")}</div>

    ${S_("Attack pattern, detection & mitigation", "ttp")}
    <div class="grid g-2">${(r.patterns || []).map((p) => `<div class="card"><h3>${p.icon} ${esc(p.name)}</h3><p class="secondary" style="margin:6px 0 10px">${esc(p.summary)}</p>
      <div class="grid g-2" style="gap:12px"><div><b>🔍 What to detect</b><ul class="clean">${p.detection.map((d) => `<li>${esc(d)}</li>`).join("")}</ul></div>
      <div><b>🛡 Mitigations</b><ul class="clean">${p.mitigations.map((d) => `<li>${esc(d)}</li>`).join("")}</ul></div></div></div>`).join("")}</div>

    ${S_("SIEM hunt queries", "queries")}
    <div class="card" id="qbox">${queryPanel(r.queries)}</div>

    ${S_(`Indicators of compromise (${iocs.length})`, "iocs")}
    <div class="card">${iocs.length ? `<div class="tags no-print" style="margin-bottom:10px"><button class="btn sm" id="ioc-copy">📋 Copy all</button><button class="btn sm" id="ioc-csv">⬇ CSV</button><button class="btn sm" id="ioc-hunt">🔎 Open in Query Builder</button></div>
      <div class="table-wrap"><table class="t"><thead><tr><th>Type</th><th>Indicator</th><th>Source / context</th><th>Pivot</th></tr></thead><tbody>
      ${iocs.slice(0, 300).map((i) => `<tr><td>${esc(i.type)}</td><td class="mono">${esc(i.value)}</td><td class="muted">${esc(i.source || i.threat_type || "")} ${i.first_seen ? "· " + esc(i.first_seen.slice(0, 10)) : ""}</td><td>${pivots(i)}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty">No IOCs published for this threat yet. Use the behavioural hunt queries above.</div>`}</div>

    ${r.cves?.length ? `${S_("Related vulnerabilities", "cves")}<div class="card"><div class="tags">${r.cves.map((x) => `<span class="pill click mono" data-cve="${esc(x)}">${esc(x)}</span>`).join("")}</div>
      ${r.cve_details?.length ? `<div class="mt">${cveMiniTable(r.cve_details, false)}</div>` : ""}</div>` : ""}

    ${S_("Targeting: industries, regions & actors", "targets")}
    <div class="grid g-3">
      <div class="card"><h3>Industries</h3><div id="rb-ind">${barList(r.industries, { unit: "mentions" })}</div></div>
      <div class="card"><h3>Regions</h3><div id="rb-reg">${barList(r.regions, { unit: "mentions" })}</div></div>
      <div class="card"><h3>Threat actors</h3><div id="rb-act">${barList(r.actors, { unit: "mentions" })}</div></div></div>

    ${S_(`Source reporting (${(r.articles || []).length})`, "sources")}
    <div class="card">${(r.articles || []).map((a) => `<div class="feed-item"><div class="feed-bar" style="background:var(--${sevVar(a.severity)})"></div><div>
       <a class="feed-title" style="font-size:14px" href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.title)}</a>
       <div class="feed-meta"><b>${esc(a.source)}</b><span>${esc((a.published || "").slice(0, 10))}</span></div><div class="feed-sum clamp2">${esc(a.summary)}</div></div></div>`).join("") || '<div class="empty">No press coverage yet.</div>'}
      ${(r.references || []).length ? `<h3 class="mt">References</h3><ul class="clean">${r.references.map((u) => `<li><a href="${esc(u)}" target="_blank" rel="noopener" class="mono">${esc(u)}</a></li>`).join("")}</ul>` : ""}</div>`;

  wireQueryPanel($("#qbox"));
  ["#rb-ind", "#rb-reg", "#rb-act"].forEach((s) => wireBars($(s)));
  $("#r-print").onclick = () => window.print();
  $("#r-json").onclick = () => download(`${rid}.json`, JSON.stringify(r, null, 2), "application/json");
  $("#r-md").onclick = () => download(`${rid}.md`, reportMarkdown(r), "text/markdown");
  if (iocs.length) {
    $("#ioc-copy").onclick = (e) => copy(iocs.map((i) => i.value).join("\n"), e.target);
    $("#ioc-csv").onclick = () => download(`${rid}-iocs.csv`, "type,value,source\n" + iocs.map((i) => `${i.type},"${i.value}",${i.source || ""}`).join("\n"), "text/csv");
    $("#ioc-hunt").onclick = () => { sessionStorage.setItem("hunt", iocs.map((i) => i.value).join("\n")); location.hash = "#/hunt"; };
  }
  $$(".toc a[href^='#']").forEach((a) => a.onclick = (e) => { e.preventDefault(); document.getElementById(a.getAttribute("href").slice(1))?.scrollIntoView({ behavior: "smooth" }); });
};
function reportMarkdown(r) {
  const L = [`# ${r.title}`, "", `**Severity:** ${r.severity} · **Type:** ${kindLabel(r.kind)} · **Generated:** ${r.generated || r.updated}`, "", "## Executive summary", r.executive_summary, "", "## Attack chain"];
  (r.chain || []).forEach((s, i) => L.push(`${i + 1}. **${s.stage}** — ${s.description} (${s.techniques.map((t) => `${t.id} ${t.name}`).join(", ")})`));
  (r.patterns || []).forEach((p) => { L.push("", `## ${p.name}`, "**Detect:**", ...p.detection.map((d) => `- ${d}`), "**Mitigate:**", ...p.mitigations.map((d) => `- ${d}`)); });
  L.push("", "## Hunt queries");
  const q = r.queries || {}, names = q.siems || {};
  for (const [sec, label] of [["ioc", "IOC match"], ["cve", "Vulnerability exposure"]]) for (const [k, v] of Object.entries(q[sec] || {})) L.push("", `### ${label} — ${names[k] || k}`, "```", v, "```");
  for (const [, b] of Object.entries(q.behaviour || {})) for (const [k, v] of Object.entries(b.queries)) L.push("", `### Behaviour (${b.name}) — ${names[k] || k}`, "```", v, "```");
  L.push("", "## IOCs", ...(r.iocs || []).map((i) => `- ${i.type}: \`${i.value}\``), "", "## CVEs", ...(r.cves || []).map((c) => `- ${c}`), "", "## Sources", ...(r.articles || []).map((a) => `- [${a.title}](${a.url}) — ${a.source}`));
  return L.join("\n");
}

// ------------------------------------------------------------------ Query panel (shared)
const SIEM_ORDER = ["secops", "yaral", "splunk", "sentinel", "elastic", "qradar"];
const SIEM_SHORT = { secops: "Google SecOps · UDM", yaral: "Google SecOps · YARA-L", splunk: "Splunk", sentinel: "Sentinel / Defender", elastic: "Elastic", qradar: "QRadar" };
function queryPanel(q) {
  if (!q) return '<div class="empty">No queries</div>';
  const has = (k) => q.ioc?.[k] || q.cve?.[k] || Object.values(q.behaviour || {}).some((b) => b.queries[k]);
  const siems = SIEM_ORDER.filter(has);
  if (!siems.length) return '<div class="empty">No indicators to build queries from.</div>';
  const block = (label, code) => code ? `<div class="code-label">${label}</div><div class="code"><button class="btn sm copy">📋 Copy</button><pre>${esc(code)}</pre></div>` : "";
  return `<div class="qtabs no-print">${siems.map((k, i) => `<button data-s="${k}" class="${i ? "" : "on"}">${SIEM_SHORT[k]}</button>`).join("")}</div>
    ${siems.map((k, i) => `<div class="qpane" data-s="${k}" ${i ? "hidden" : ""}>
      ${block("🧬 IOC sweep — search the last 30 days for any reported indicator", q.ioc?.[k])}
      ${block("🐞 Vulnerability exposure — find vulnerable assets / exploitation signatures", q.cve?.[k])}
      ${Object.values(q.behaviour || {}).map((b) => block(`🎯 Behavioural hunt — ${esc(b.name)} (works even without IOCs)`, b.queries[k])).join("")}
    </div>`).join("")}
    <div class="muted" style="font-size:12px">Field names follow the default schema of each SIEM (UDM, CIM, ASIM/MDE, ECS). Adjust index / table names for your environment.</div>`;
}
function wireQueryPanel(root) {
  $$(".qtabs button", root).forEach((b) => b.onclick = () => {
    $$(".qtabs button", root).forEach((x) => x.classList.toggle("on", x === b));
    $$(".qpane", root).forEach((p) => (p.hidden = p.dataset.s !== b.dataset.s));
  });
  $$(".code .copy", root).forEach((b) => b.onclick = () => copy($("pre", b.parentElement).textContent, b));
}

// ------------------------------------------------------------------ Vulnerabilities
VIEWS.vulns = async (qp) => {
  const st = { kev: qp.get("kev") || "", sort: qp.get("sort") || "", min_cvss: "", ransomware: "", page: 1 };
  VIEW().innerHTML = head("Vulnerability Intelligence", "CISA KEV · NVD · CVE.org · FIRST EPSS — prioritise by exploitation, not just CVSS",
    `<label class="pill click"><input type="checkbox" id="v-kev" ${st.kev ? "checked" : ""}> KEV only</label>
     <label class="pill click"><input type="checkbox" id="v-rw"> Ransomware use</label>
     <select class="ctl" id="v-cvss"><option value="">Any CVSS</option><option value="9">≥ 9.0 critical</option><option value="7">≥ 7.0 high</option><option value="4">≥ 4.0</option></select>
     <select class="ctl" id="v-sort"><option value="">Newest</option><option value="kev">KEV date</option><option value="cvss">CVSS</option><option value="epss">EPSS</option><option value="mentions">Most discussed</option></select>`) +
    `<div class="card"><div class="sub" id="v-total"></div><div class="table-wrap"><table class="t"><thead><tr><th>CVE</th><th>Vendor / product</th><th>Description</th><th>CVSS</th><th>EPSS</th><th>Pattern</th><th>Published</th></tr></thead>
     <tbody id="v-body"></tbody></table></div><div style="text-align:center" class="mt"><button class="btn" id="v-more" hidden>Load more</button></div></div>`;
  $("#v-sort").value = st.sort;
  const load = async (append) => {
    const d = await api("/api/cves", { ...range(), q: S.filters.q, attack: S.filters.attack, kev: st.kev, sort: st.sort, min_cvss: st.min_cvss, ransomware: st.ransomware, page: st.page, limit: 50 });
    $("#v-total").textContent = `${fmt(d.total)} CVEs · ${filterSummary()}`;
    const html = d.items.map((c) => `<tr class="click" data-go="report/cve-${esc(c.cve_id)}"><td class="mono" style="white-space:nowrap">${esc(c.cve_id)}<div class="tags" style="margin-top:3px">${c.kev ? kevPill() : ""}${c.ransomware === "Known" ? '<span class="pill">🔒 ransomware</span>' : ""}</div></td>
      <td>${esc(c.vendor || "—")}<div class="muted">${esc(c.product || "")}</div></td><td><div class="clamp2 secondary" style="max-width:520px">${esc(c.description)}</div></td>
      <td>${cvssBadge(c.cvss)}</td><td>${epssBar(c.epss)}</td><td>${(c.attack_types || []).slice(0, 1).map((t) => PATTERN[t] ? `<span title="${esc(PATTERN[t].name)}">${PATTERN[t].icon}</span>` : "").join("")}</td>
      <td class="muted" style="white-space:nowrap">${esc((c.published || c.kev_added || "").slice(0, 10))}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">No CVEs match. Try “All time”.</td></tr>`;
    if (append) $("#v-body").insertAdjacentHTML("beforeend", html); else $("#v-body").innerHTML = html;
    $("#v-more").hidden = st.page * 50 >= d.total;
  };
  const re = () => { st.page = 1; load(); };
  $("#v-kev").onchange = (e) => { st.kev = e.target.checked ? "1" : ""; re(); };
  $("#v-rw").onchange = (e) => { st.ransomware = e.target.checked ? "1" : ""; re(); };
  $("#v-cvss").onchange = (e) => { st.min_cvss = e.target.value; re(); };
  $("#v-sort").onchange = (e) => { st.sort = e.target.value; re(); };
  $("#v-more").onclick = () => { st.page++; load(true); };
  await load();
};

// ------------------------------------------------------------------ IOCs
VIEWS.iocs = async (qp) => {
  const st = { type: "", source: "", malware: qp.get("malware") || "", page: 1 };
  const srcs = S.meta.ioc_sources || [];
  VIEW().innerHTML = head("Indicators of Compromise", "abuse.ch ThreatFox · URLhaus · Feodo Tracker · AlienVault OTX · IOCs extracted from research",
    `<div class="seg-toggle" id="i-type">${[["", "All"], ["ip", "IP"], ["domain", "Domain"], ["url", "URL"], ["sha256", "SHA256"], ["md5", "MD5"]].map(([k, l]) => `<button data-k="${k}" class="${k ? "" : "on"}">${l}</button>`).join("")}</div>
     <select class="ctl" id="i-src"><option value="">All IOC sources</option>${srcs.map((s) => `<option>${esc(s)}</option>`).join("")}</select>
     <input class="ctl" id="i-mal" placeholder="Malware family" value="${esc(st.malware)}">
     <button class="btn" id="i-csv">⬇ Export CSV</button><button class="btn primary" id="i-hunt">🔎 Hunt these</button>`) +
    `<div class="card"><div class="sub" id="i-total"></div><div class="table-wrap"><table class="t"><thead><tr><th>Indicator</th><th>Type</th><th>Malware / threat</th><th>Source</th><th>First seen</th><th>Pivot</th><th></th></tr></thead>
     <tbody id="i-body"></tbody></table></div><div style="text-align:center" class="mt"><button class="btn" id="i-more" hidden>Load more</button></div></div>`;
  let current = [];
  const q = () => ({ ...range(), q: S.filters.q, type: st.type, source: st.source, malware: st.malware });
  const load = async (append) => {
    const d = await api("/api/iocs", { ...q(), page: st.page, limit: 100 });
    current = append ? current.concat(d.items) : d.items;
    $("#i-total").textContent = `${fmt(d.total)} indicators · ${filterSummary()}`;
    const html = d.items.map((i) => `<tr><td class="mono">${esc(i.value)}</td><td>${esc(i.type)}</td><td>${esc(i.malware || "—")}<div class="muted">${esc(i.threat_type || "")}</div></td>
      <td>${i.reference ? `<a href="${esc(i.reference)}" target="_blank" rel="noopener">${esc(i.source)}</a>` : esc(i.source)}</td>
      <td class="muted" style="white-space:nowrap" title="${esc(i.first_seen)}">${ago(i.first_seen)}</td><td>${pivots(i)}</td>
      <td><button class="btn sm cp" data-v="${esc(i.value)}">📋</button></td></tr>`).join("") || `<tr><td colspan="7" class="empty">No IOCs match. Try “All time”, or add an abuse.ch / OTX key on the Sources page.</td></tr>`;
    if (append) $("#i-body").insertAdjacentHTML("beforeend", html); else $("#i-body").innerHTML = html;
    $$("#i-body .cp").forEach((b) => b.onclick = () => copy(b.dataset.v, b));
    $("#i-more").hidden = st.page * 100 >= d.total;
  };
  const re = () => { st.page = 1; load(); };
  $$("#i-type button").forEach((b) => b.onclick = () => { st.type = b.dataset.k; $$("#i-type button").forEach((x) => x.classList.toggle("on", x === b)); re(); });
  $("#i-src").onchange = (e) => { st.source = e.target.value; re(); };
  let t; $("#i-mal").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { st.malware = e.target.value.trim(); re(); }, 350); };
  $("#i-csv").onclick = () => { const u = new URL("/api/iocs/export", location.origin); Object.entries(q()).forEach(([k, v]) => v && u.searchParams.set(k, v)); location.href = u; };
  $("#i-hunt").onclick = () => { sessionStorage.setItem("hunt", current.slice(0, 200).map((i) => i.value).join("\n")); location.hash = "#/hunt"; };
  $("#i-more").onclick = () => { st.page++; load(true); };
  await load();
};

// ------------------------------------------------------------------ Attack patterns
VIEWS.patterns = async (qp) => {
  VIEW().innerHTML = head("Attack Patterns & Playbooks", `How each attack type works, how to detect it and how to stop it · ${esc(filterSummary())}`) + loading(6);
  const seq = renderSeq;
  const d = await api("/api/patterns", params());
  if (seq !== renderSeq) return;
  const sel = qp.get("p");
  const maxT = Math.max(1, ...d.techniques.map((t) => t.count));
  VIEW().innerHTML = head("Attack Patterns & Playbooks", `How each attack type works, how to detect it and how to stop it · ${esc(filterSummary())}`) +
    `<div class="grid g-cards">${d.patterns.map((p) => `<div class="card pattern-card" data-go="patterns?p=${p.key}" ${sel === p.key ? 'style="border-color:var(--accent)"' : ""}>
       <div class="card-head"><span class="pattern-icon">${p.icon}</span><div style="text-align:right"><div class="pattern-count">${fmt(p.count)}</div><div class="muted" style="font-size:11.5px">reports in range</div></div></div>
       <h3>${esc(p.name)}</h3><div class="secondary clamp2" style="font-size:13px;margin-top:4px">${esc(p.summary)}</div>
       <div class="muted" style="font-size:12px;margin-top:8px">${p.chain.length} stages · ${p.chain.reduce((a, s) => a + s.techniques.length, 0)} ATT&CK techniques</div></div>`).join("")}</div>
    <div id="p-detail"></div>
    <div class="card mt"><h3>ATT&CK technique heat — weighted by current threat volume</h3><div class="sub">Techniques most relevant to what's trending right now (darker = more relevant). Click to open in MITRE ATT&CK.</div>
      <div class="tags">${d.techniques.map((t) => { const a = 0.15 + 0.85 * (t.count / maxT); return `<a class="tech" target="_blank" rel="noopener" href="${esc(t.url)}" data-tt="${esc(t.id)} ${esc(t.name)} — weight ${fmt(t.count)}"
         style="background:color-mix(in srgb, var(--ramp-400) ${Math.round(a * 100)}%, var(--surface-1));color:${a > .55 ? "#fff" : "var(--text-primary)"};border-color:transparent"><b style="color:inherit">${esc(t.id)}</b>${esc(t.name)}</a>`; }).join("")}</div></div>`;
  $$("[data-tt]", VIEW()).forEach((r) => { r.onmousemove = (e) => TT.show(esc(r.dataset.tt), e.clientX, e.clientY); r.onmouseleave = () => TT.hide(); });
  if (sel) {
    const p = d.patterns.find((x) => x.key === sel);
    if (p) {
      $("#p-detail").innerHTML = `<div class="report-hero mt"><div class="tags"><span class="pattern-icon">${p.icon}</span></div><h1>${esc(p.name)}</h1><div class="summary">${esc(p.summary)}</div>
        <div class="toc"><button class="btn sm" data-filter-attack="${p.key}">Filter dashboard to this pattern</button><a class="btn sm" href="#/reports?kind=trend">Trend reports</a></div></div>
        <div class="section-title"><span class="num">1</span>Attack flow — how it is carried out</div>
        <div class="chain">${p.chain.map((s, i) => `<div class="stage"><div class="stage-n">Stage ${i + 1}</div><h4>${esc(s.stage)}</h4><p>${esc(s.description)}</p>
          <div>${s.techniques.map((t) => `<a class="tech" href="${esc(t.url)}" target="_blank" rel="noopener"><b>${esc(t.id)}</b>${esc(t.name)}</a>`).join("")}</div>
          ${s.defend?.length ? `<div class="defend">🛡 ${s.defend.map(esc).join(" · ")}</div>` : ""}</div>`).join("")}</div>
        <div class="grid g-2 mt"><div class="card"><h3>🔍 What to detect</h3><ul class="clean">${p.detection.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
        <div class="card"><h3>🛡 Mitigations</h3><ul class="clean">${p.mitigations.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div></div>
        <div class="section-title"><span class="num">2</span>Behavioural hunt queries</div>
        <div class="card" id="p-q">${queryPanel({ behaviour: Object.keys(p.queries).length ? { [p.key]: { name: p.name, queries: p.queries } } : {} })}</div>`;
      wireQueryPanel($("#p-q"));
      $("[data-filter-attack]").onclick = () => { setFilter("attack", p.key); location.hash = "#/overview"; };
      $("#p-detail").scrollIntoView({ behavior: "smooth" });
    }
  }
};

// ------------------------------------------------------------------ Query builder
VIEWS.hunt = async () => {
  const pre = sessionStorage.getItem("hunt") || ""; sessionStorage.removeItem("hunt");
  VIEW().innerHTML = head("Hunt Query Builder", "Paste IOCs or CVEs (any format, defanged OK) → ready-to-run queries for Google SecOps, Splunk, Sentinel, Elastic and QRadar") +
    `<div class="grid g-21"><div class="card"><h3>Indicators</h3><div class="sub">IPs, domains, URLs, hashes (MD5/SHA1/SHA256) and CVE IDs — one per line or comma separated</div>
       <textarea class="ctl" id="h-text" placeholder="185.220.101[.]4&#10;evil-login[.]example&#10;hxxps://bad.example/payload.exe&#10;44d88612fea8a8f36de82e1278abb02f&#10;CVE-2024-3400">${esc(pre)}</textarea>
       <div class="tags mt"><input class="ctl" id="h-title" placeholder="Rule / hunt name (optional)" style="flex:1"><button class="btn primary" id="h-go">⚡ Generate queries</button></div></div>
     <div class="card"><h3>Add behavioural hunts</h3><div class="sub">Optional: include TTP-based queries for these attack patterns</div>
       <div style="display:flex;flex-direction:column;gap:6px">${S.meta.attack_types.filter((a) => a.key !== "vulnerability").map((a) => `<label><input type="checkbox" class="h-at" value="${a.key}"> ${a.icon} ${esc(a.name)}</label>`).join("")}</div></div></div>
    <div class="card mt" id="h-out"><div class="empty">Queries will appear here.</div></div>`;
  const go = async () => {
    const body = { text: $("#h-text").value, title: $("#h-title").value, attack_types: $$(".h-at:checked").map((c) => c.value) };
    const d = await api("/api/query-builder", {}, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const counts = d.iocs.reduce((a, i) => ((a[i.type] = (a[i.type] || 0) + 1), a), {});
    $("#h-out").innerHTML = `<div class="tags" style="margin-bottom:10px">${Object.entries(counts).map(([k, v]) => `<span class="pill">${k} · ${v}</span>`).join("")}${d.cves.map((c) => `<span class="pill mono">${c}</span>`).join("")}</div>` + queryPanel(d);
    wireQueryPanel($("#h-out"));
  };
  $("#h-go").onclick = go;
  if (pre) go();
};

// ------------------------------------------------------------------ Sources
VIEWS.sources = async () => {
  const seq = renderSeq;
  const d = await api("/api/sources");
  if (seq !== renderSeq) return;
  const sc = d.scheduler;
  VIEW().innerHTML = head("Intelligence Sources", `Collection runs every ${S.meta.refresh_minutes} minutes · history is retained forever`,
    `<button class="btn primary" id="s-run" ${sc.running ? "disabled" : ""}>${sc.running ? "Collecting…" : "⟳ Collect now"}</button>`) +
    `<div class="grid g-kpi"><div class="card kpi"><div class="k-label">Last cycle</div><div class="k-val" style="font-size:18px">${sc.last_end ? ago(sc.last_end) : "—"}</div><div class="k-note">${esc(sc.last_end || "")}</div></div>
      <div class="card kpi"><div class="k-label">Healthy</div><div class="k-val">${d.sources.filter((s) => s.status === "ok").length}</div><div class="k-note">of ${d.sources.length} sources</div></div></div>
    <div class="card mt"><h3>Add a custom RSS / Atom feed</h3><div class="sub">Any vendor blog, CERT advisory feed or research site</div>
      <div class="tags"><input class="ctl" id="s-name" placeholder="Name (e.g. CERT-EU)"><input class="ctl" id="s-url" placeholder="https://example.org/feed.xml" style="flex:1;min-width:240px"><button class="btn" id="s-add">+ Add feed</button></div>
      <div id="s-msg" class="muted" style="margin-top:6px"></div></div>
    <div class="card mt"><div class="table-wrap"><table class="t"><thead><tr><th>Source</th><th>Type</th><th>Status</th><th>Last OK</th><th>New</th><th>Total</th><th>Message</th><th></th></tr></thead><tbody>
    ${d.sources.map((s) => `<tr><td><b>${esc(s.name)}</b><div class="muted mono" style="font-size:11px">${esc(s.url)}</div></td><td>${esc(s.kind)}</td>
      <td class="status-${s.status}">${s.status === "ok" ? "● OK" : "▲ Error"}</td><td class="muted">${s.last_ok ? ago(s.last_ok) : "never"}</td>
      <td class="num">${fmt(s.items)}</td><td class="num">${fmt(s.total)}</td><td class="muted" style="max-width:360px">${esc(s.message)}</td>
      <td>${s.custom ? `<button class="btn sm s-del" data-n="${esc(s.name)}">Remove</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="8" class="empty">No collection has run yet — click “Collect now”.</td></tr>'}
    </tbody></table></div></div>
    <div class="notice mt">🔑 Optional free API keys unlock more IOC sources: <b>ABUSECH_AUTH_KEY</b> (ThreatFox / URLhaus — auth.abuse.ch), <b>OTX_API_KEY</b> (AlienVault OTX pulses), <b>NVD_API_KEY</b> (higher NVD rate limits). Set them as environment variables before starting the server.</div>`;
  $("#s-run").onclick = triggerCollect;
  $("#s-add").onclick = async () => {
    $("#s-msg").textContent = "Fetching…";
    try {
      const r = await api("/api/sources", {}, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: $("#s-name").value, url: $("#s-url").value }) });
      $("#s-msg").textContent = `Added ${r.added}: ${r.new_items} new items`; setTimeout(render, 800);
    } catch (e) { $("#s-msg").textContent = "Could not add feed: " + e.message; }
  };
  $$(".s-del").forEach((b) => b.onclick = async () => { await fetch(`/api/sources/${encodeURIComponent(b.dataset.n)}`, { method: "DELETE" }); render(); });
};

// ------------------------------------------------------------------ Toolkit
VIEWS.toolkit = async () => {
  const seq = renderSeq;
  const d = await api("/api/toolkit");
  if (seq !== renderSeq) return;
  const cats = [...new Set(d.items.map((i) => i.cat))];
  VIEW().innerHTML = head("Analyst Toolkit", "Essential cybersecurity resources — ✓ marks sources ThreatPulse ingests automatically") +
    cats.map((c) => `<h3 class="section-title">${esc(c)}</h3><div class="grid g-cards" style="grid-template-columns:repeat(auto-fill,minmax(240px,1fr))">
      ${d.items.filter((i) => i.cat === c).map((i) => `<a class="card tool-card pattern-card" href="${esc(i.url)}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none">
        <div class="card-head" style="margin:0"><span class="t-name">${esc(i.name)}</span>${i.ingested ? '<span class="pill" style="color:var(--good-text)">✓ ingested</span>' : ""}</div>
        <div class="secondary" style="font-size:13px">${esc(i.desc)}</div><div class="muted mono" style="font-size:11px">${esc(i.url.replace(/^https?:\/\//, ""))}</div></a>`).join("")}</div>`).join("");
};

// ================================================================== router / chrome
function parseHash() {
  const h = location.hash.replace(/^#\/?/, "") || "overview";
  const [path, qs] = h.split("?");
  const [route, ...rest] = path.split("/");
  return { route, arg: rest.join("/"), qp: new URLSearchParams(qs || "") };
}
let renderSeq = 0;
async function render() {
  const { route, arg, qp } = parseHash();
  S.route = route;
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.r === route || (route === "report" && a.dataset.r === "reports")));
  $("#sidebar").classList.remove("open");
  const fn = VIEWS[route] || VIEWS.overview;
  const seq = ++renderSeq;
  try { await fn(qp, arg); }
  catch (e) { if (seq === renderSeq) VIEW().innerHTML = `<div class="card empty">Something went wrong: ${esc(e.message)}</div>`; console.error(e); }
  if (seq === renderSeq) wireGo();
}
function wireGo() {
  $$("[data-go]").forEach((el) => {
    if (el.__go) return; el.__go = 1;
    el.addEventListener("click", (e) => {
      const inner = e.target.closest("a,button,input,label,details,[data-cve],[data-attack],[data-industry],[data-region],[data-actor],[data-go]");
      if (inner && inner !== el) return; // nested links / pills handle themselves
      location.hash = "#/" + el.dataset.go;
    });
  });
}

function syncFilterUI() {
  const f = S.filters;
  $("#f-period").value = f.period;
  ["industry", "region", "attack"].forEach((k) => ($(`#f-${k}`).value = f[k]));
  $("#q").value = f.q;
  $("#f-year").hidden = f.period !== "year"; $("#f-month").hidden = f.period !== "month"; $("#f-day").hidden = f.period !== "day";
  $("#f-from").hidden = $("#f-to").hidden = f.period !== "custom";
  if (f.year) $("#f-year").value = f.year; $("#f-month").value = f.month; $("#f-day").value = f.day; $("#f-from").value = f.from; $("#f-to").value = f.to;
}
function saveFilters() { try { localStorage.setItem("tp-filters", JSON.stringify(S.filters)); } catch (e) { /* ignore */ } }
function loadFilters() { try { Object.assign(S.filters, JSON.parse(localStorage.getItem("tp-filters") || "{}")); } catch (e) { /* ignore */ } }

function initFilters() {
  const m = S.meta;
  const opt = (v, l) => `<option value="${esc(v)}">${esc(l)}</option>`;
  $("#f-industry").insertAdjacentHTML("beforeend", m.industries.map((i) => opt(i, i)).join(""));
  $("#f-region").insertAdjacentHTML("beforeend", m.regions.map((i) => opt(i, i)).join(""));
  $("#f-attack").insertAdjacentHTML("beforeend", m.attack_types.map((a) => opt(a.key, `${a.icon} ${a.name}`)).join(""));
  const thisYear = new Date().getUTCFullYear();
  const years = [...new Set([...m.years, ...Array.from({ length: 6 }, (_, i) => String(thisYear - i))])].sort().reverse();
  $("#f-year").innerHTML = years.map((y) => opt(y, y)).join("");
  const onChange = () => {
    const f = S.filters;
    f.period = $("#f-period").value;
    if (f.period === "year" && !f.year) f.year = $("#f-year").value || String(thisYear);
    if (f.period === "month" && !f.month) f.month = new Date().toISOString().slice(0, 7);
    if (f.period === "day" && !f.day) f.day = isoDay(new Date());
    ["industry", "region", "attack"].forEach((k) => (f[k] = $(`#f-${k}`).value));
    S.gran = null; syncFilterUI(); saveFilters(); render();
  };
  ["#f-period", "#f-industry", "#f-region", "#f-attack"].forEach((s) => $(s).addEventListener("change", onChange));
  [["#f-year", "year"], ["#f-month", "month"], ["#f-day", "day"], ["#f-from", "from"], ["#f-to", "to"]].forEach(([s, k]) =>
    $(s).addEventListener("change", (e) => { S.filters[k] = e.target.value; saveFilters(); render(); }));
  let t; $("#q").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { S.filters.q = e.target.value.trim(); saveFilters(); render(); }, 400); });
  $("#f-clear").onclick = () => { Object.assign(S.filters, { period: "90d", industry: "", region: "", attack: "", q: "", from: "", to: "" }); S.gran = null; syncFilterUI(); saveFilters(); render(); };
}

// ------------------------------------------------------------------ live updates
async function triggerCollect() {
  await fetch("/api/collect", { method: "POST" });
  toast("Collection started — pulling all sources…");
  setLive(true);
}
function setLive(busy, text) {
  $("#live-dot").classList.toggle("busy", !!busy);
  $("#live-text").textContent = text || (busy ? "Collecting…" : "Live");
}
function toast(html, action) {
  const t = $("#toast");
  t.innerHTML = `<div style="flex:1">${html}</div>${action ? `<button class="btn sm primary" id="toast-act">${action}</button>` : ""}<button class="btn sm ghost" id="toast-x">✕</button>`;
  t.classList.add("on");
  $("#toast-x").onclick = () => t.classList.remove("on");
  if (action) $("#toast-act").onclick = () => { t.classList.remove("on"); render(); };
  if (!action) setTimeout(() => t.classList.remove("on"), 4000);
}
let wasRunning = false;
async function poll() {
  try {
    const u = await api("/api/updates", { since: S.lastSync });
    const sc = u.scheduler;
    setLive(sc.running, sc.running ? "Collecting…" : `Live · synced ${ago(sc.last_end) || "—"}`);
    if (u.articles > 0) {
      const top = u.latest[0];
      toast(`<b>${u.articles} new item${u.articles > 1 ? "s" : ""}</b>${top ? `<div class="secondary clamp2" style="font-size:12.5px">${esc(top.source)}: ${esc(top.title)}</div>` : ""}`, "Show");
      S.lastSync = u.now;
    } else if (wasRunning && !sc.running) {
      S.lastSync = u.now;
      if (["overview", "sources"].includes(S.route)) render();
    }
    wasRunning = sc.running;
  } catch (e) { setLive(false, "Offline"); }
}

// ------------------------------------------------------------------ boot
(async function boot() {
  TT.el = $("#tooltip");
  try { const th = localStorage.getItem("tp-theme"); if (th) document.documentElement.dataset.theme = th; } catch (e) { /* ignore */ }
  $("#theme-btn").onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("tp-theme", next); } catch (e) { /* ignore */ }
    render();
  };
  $("#menu-btn").onclick = () => $("#sidebar").classList.toggle("open");
  $("#refresh-btn").onclick = triggerCollect;
  S.meta = await api("/api/meta");
  S.meta.attack_types.forEach((a) => (PATTERN[a.key] = a));
  $("#sidebar-foot").textContent = `Auto-refresh every ${S.meta.refresh_minutes} min · history retained`;
  loadFilters(); initFilters(); syncFilterUI();
  addEventListener("hashchange", render);
  let rt; addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => S.route === "overview" && render(), 300); });
  await render();
  poll(); setInterval(poll, 30000);
})();

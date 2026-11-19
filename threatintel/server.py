"""HTTP API + static web UI (Python standard library only)."""
import csv
import io
import json
import logging
import mimetypes
import os
import re
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import collectors, config, db, enrich, queries, reports, scheduler
from .knowledge import ATTACK_PATTERNS, INDUSTRIES, REGIONS, TOOLKIT

log = logging.getLogger("server")
BUCKET = {"hour": 13, "day": 10, "month": 7, "year": 4}


# ------------------------------------------------------------------ filters
def article_where(p, prefix=""):
    w, a = [], []
    if p.get("from"):
        w.append(f"{prefix}published >= ?"); a.append(p["from"])
    if p.get("to"):
        w.append(f"{prefix}published <= ?"); a.append(p["to"] + ("T23:59:59Z" if len(p["to"]) == 10 else ""))
    for key, col in (("industry", "industries"), ("region", "regions"), ("attack", "attack_types")):
        if p.get(key):
            vals = p[key].split(",")
            w.append("(" + " OR ".join(f"{prefix}{col} LIKE ?" for _ in vals) + ")")
            a += [f'%"{v}"%' for v in vals]
    if p.get("source"):
        vals = p["source"].split(",")
        w.append(f"{prefix}source IN ({','.join('?' * len(vals))})"); a += vals
    if p.get("severity"):
        vals = p["severity"].split(",")
        w.append(f"{prefix}severity IN ({','.join('?' * len(vals))})"); a += vals
    if p.get("q"):
        q = f"%{p['q']}%"
        w.append(f"({prefix}title LIKE ? OR {prefix}summary LIKE ? OR {prefix}cves LIKE ? OR {prefix}actors LIKE ? OR {prefix}iocs LIKE ?)")
        a += [q] * 5
    return (" WHERE " + " AND ".join(w)) if w else "", a


def _date_where(p, col):
    w, a = [], []
    if p.get("from"):
        w.append(f"{col} >= ?"); a.append(p["from"])
    if p.get("to"):
        w.append(f"{col} <= ?"); a.append(p["to"] + ("T23:59:59Z" if len(p["to"]) == 10 else ""))
    return w, a


def _page(p, default=50):
    lim = max(1, min(int(p.get("limit", default)), 1000))
    off = max(0, int(p.get("page", 1)) - 1) * lim
    return lim, off


# ------------------------------------------------------------------ handlers
def api_meta(p):
    years = [r["y"] for r in db.query("SELECT DISTINCT substr(published,1,4) y FROM articles WHERE published IS NOT NULL ORDER BY y DESC")]
    return {
        "attack_types": [{"key": k, "name": v["name"], "icon": v["icon"], "color": v["color"]} for k, v in ATTACK_PATTERNS.items()],
        "industries": list(INDUSTRIES.keys()), "regions": list(REGIONS.keys()),
        "sources": [r["source"] for r in db.query("SELECT DISTINCT source FROM articles ORDER BY source")],
        "ioc_sources": [r["source"] for r in db.query("SELECT DISTINCT source FROM iocs ORDER BY source")],
        "years": years, "siems": queries.SIEMS, "refresh_minutes": config.REFRESH_MINUTES,
        "scheduler": scheduler.STATE,
    }


def api_stats(p):
    gran = p.get("granularity", "day")
    n = BUCKET.get(gran, 10)
    where, args = article_where(p)
    arts = db.query(f"SELECT published, attack_types, industries, regions, actors, cves, severity, source FROM articles{where}", args)

    timeline = Counter()
    by_attack_time = {}
    att, ind, reg, act, src, sev, cve_c = Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    for a in arts:
        b = (a["published"] or "")[:n]
        timeline[b] += 1
        for t in db.unj(a["attack_types"]):
            att[t] += 1
            by_attack_time.setdefault(t, Counter())[b] += 1
        for x in db.unj(a["industries"]):
            ind[x] += 1
        for x in db.unj(a["regions"]):
            reg[x] += 1
        for x in db.unj(a["actors"]):
            act[x] += 1
        for x in db.unj(a["cves"]):
            cve_c[x] += 1
        src[a["source"]] += 1
        sev[a["severity"]] += 1

    cw, ca = _date_where(p, "published")
    cve_tl = db.query(f"SELECT substr(published,1,{n}) b, COUNT(*) c FROM cves" + (" WHERE " + " AND ".join(cw) if cw else "") +
                      " GROUP BY b ORDER BY b", ca)
    kw, ka = _date_where(p, "kev_added")
    kev_count = db.one("SELECT COUNT(*) c FROM cves WHERE kev=1" + ("".join(" AND " + x for x in kw)), ka)["c"]
    iw, ia = _date_where(p, "first_seen")
    ioc_where = (" WHERE " + " AND ".join(iw)) if iw else ""
    ioc_tl = db.query(f"SELECT substr(first_seen,1,{n}) b, COUNT(*) c FROM iocs{ioc_where} GROUP BY b ORDER BY b", ia)
    ioc_types = db.query(f"SELECT type name, COUNT(*) count FROM iocs{ioc_where} GROUP BY type ORDER BY count DESC", ia)
    malware = db.query(f"SELECT malware name, COUNT(*) count FROM iocs{ioc_where}{' AND' if ioc_where else ' WHERE'} malware IS NOT NULL AND malware!='' GROUP BY malware ORDER BY count DESC LIMIT 10", ia)
    ioc_total = db.one(f"SELECT COUNT(*) c FROM iocs{ioc_where}", ia)["c"]
    cve_total = db.one("SELECT COUNT(*) c FROM cves" + (" WHERE " + " AND ".join(cw) if cw else ""), ca)["c"]

    top_cve_ids = [k for k, _ in cve_c.most_common(10)]
    trending_cves = []
    if top_cve_ids:
        rows = {r["cve_id"]: r for r in db.query(
            f"SELECT cve_id,vendor,product,cvss,severity,kev,epss FROM cves WHERE cve_id IN ({','.join('?' * len(top_cve_ids))})", top_cve_ids)}
        trending_cves = [dict(rows.get(c, {"cve_id": c}), mentions=cve_c[c]) for c in top_cve_ids]
    latest_kev = db.query("SELECT cve_id,vendor,product,kev_added,ransomware,cvss,epss FROM cves WHERE kev=1 ORDER BY kev_added DESC LIMIT 8")

    labels = sorted(timeline)
    return {
        "kpis": {"articles": len(arts), "critical": sev.get("critical", 0), "cves": cve_total, "kev": kev_count,
                 "iocs": ioc_total, "reports": db.one("SELECT COUNT(*) c FROM reports")["c"], "actors": len(act),
                 "sources": db.one("SELECT COUNT(*) c FROM source_status WHERE status='ok'")["c"]},
        "timeline": {"labels": labels, "articles": [timeline[l] for l in labels],
                     "by_attack": {k: [v.get(l, 0) for l in labels] for k, v in
                                   sorted(by_attack_time.items(), key=lambda kv: -sum(kv[1].values()))[:6]}},
        "cve_timeline": cve_tl[-60:], "ioc_timeline": ioc_tl[-60:],
        "attack_types": [{"key": k, "name": ATTACK_PATTERNS[k]["name"], "color": ATTACK_PATTERNS[k]["color"],
                          "icon": ATTACK_PATTERNS[k]["icon"], "count": v} for k, v in att.most_common() if k in ATTACK_PATTERNS],
        "industries": [{"name": k, "count": v} for k, v in ind.most_common(12)],
        "regions": [{"name": k, "count": v} for k, v in reg.most_common(12)],
        "actors": [{"name": k, "count": v} for k, v in act.most_common(10)],
        "sources": [{"name": k, "count": v} for k, v in src.most_common(25)],
        "severity": dict(sev), "ioc_types": ioc_types, "malware": malware,
        "trending_cves": trending_cves, "latest_kev": latest_kev,
        "top_reports": [dict(r) for r in db.query("SELECT rid,kind,title,severity,score,updated FROM reports ORDER BY score DESC LIMIT 8")],
    }


def api_articles(p):
    where, args = article_where(p)
    lim, off = _page(p)
    total = db.one(f"SELECT COUNT(*) c FROM articles{where}", args)["c"]
    rows = db.query(f"SELECT * FROM articles{where} ORDER BY published DESC LIMIT ? OFFSET ?", args + [lim, off])
    for r in rows:
        for k in ("attack_types", "industries", "regions", "cves", "iocs", "actors"):
            r[k] = db.unj(r[k])
    return {"total": total, "items": rows}


def api_cves(p):
    w, a = _date_where(p, "COALESCE(published, kev_added)")
    if p.get("kev") == "1":
        w.append("kev=1")
    if p.get("min_cvss"):
        w.append("cvss >= ?"); a.append(float(p["min_cvss"]))
    if p.get("severity"):
        vals = p["severity"].split(",")
        w.append(f"severity IN ({','.join('?' * len(vals))})"); a += vals
    if p.get("attack"):
        w.append("attack_types LIKE ?"); a.append(f'%"{p["attack"]}"%')
    if p.get("ransomware") == "1":
        w.append("ransomware='Known'")
    if p.get("q"):
        q = f"%{p['q']}%"
        w.append("(cve_id LIKE ? OR description LIKE ? OR vendor LIKE ? OR product LIKE ?)"); a += [q] * 4
    w.append("description IS NOT NULL")
    where = " WHERE " + " AND ".join(w)
    sort = {"cvss": "cvss DESC", "epss": "epss DESC", "mentions": "mentions DESC", "kev": "kev_added DESC"}.get(
        p.get("sort"), "COALESCE(published, kev_added) DESC")
    lim, off = _page(p)
    total = db.one(f"SELECT COUNT(*) c FROM cves{where}", a)["c"]
    rows = db.query(f"SELECT * FROM cves{where} ORDER BY {sort} NULLS LAST LIMIT ? OFFSET ?", a + [lim, off])
    for r in rows:
        r["attack_types"] = db.unj(r["attack_types"])
        r["refs"] = db.unj(r["refs"])
        if r["cvss"] is not None and r["cvss"] < 0:
            r["cvss"] = None
    return {"total": total, "items": rows}


def _ioc_where(p):
    w, a = _date_where(p, "first_seen")
    for key in ("type", "source"):
        if p.get(key):
            vals = p[key].split(",")
            w.append(f"{key} IN ({','.join('?' * len(vals))})"); a += vals
    if p.get("malware"):
        w.append("malware = ?"); a.append(p["malware"])
    if p.get("q"):
        q = f"%{p['q']}%"
        w.append("(value LIKE ? OR malware LIKE ? OR tags LIKE ? OR threat_type LIKE ?)"); a += [q] * 4
    return (" WHERE " + " AND ".join(w)) if w else "", a


def api_iocs(p):
    where, a = _ioc_where(p)
    lim, off = _page(p, 100)
    total = db.one(f"SELECT COUNT(*) c FROM iocs{where}", a)["c"]
    rows = db.query(f"SELECT * FROM iocs{where} ORDER BY first_seen DESC LIMIT ? OFFSET ?", a + [lim, off])
    for r in rows:
        r["tags"] = db.unj(r["tags"])
    return {"total": total, "items": rows}


def api_iocs_export(p):
    where, a = _ioc_where(p)
    rows = db.query(f"SELECT value,type,source,malware,threat_type,confidence,first_seen,last_seen,reference FROM iocs{where} "
                    "ORDER BY first_seen DESC LIMIT 50000", a)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["value", "type", "source", "malware", "threat_type", "confidence", "first_seen", "last_seen", "reference"])
    for r in rows:
        w.writerow([r[k] for k in r])
    return buf.getvalue()


def api_reports(p):
    w, a = _date_where(p, "updated")
    if p.get("kind"):
        vals = p["kind"].split(",")
        w.append(f"kind IN ({','.join('?' * len(vals))})"); a += vals
    if p.get("severity"):
        vals = p["severity"].split(",")
        w.append(f"severity IN ({','.join('?' * len(vals))})"); a += vals
    for key in ("industry", "region", "attack"):
        if p.get(key):
            w.append("data LIKE ?"); a.append(f'%"{p[key]}"%')
    if p.get("q"):
        w.append("(title LIKE ? OR data LIKE ?)"); a += [f"%{p['q']}%"] * 2
    where = (" WHERE " + " AND ".join(w)) if w else ""
    sort = "updated DESC" if p.get("sort") == "recent" else "score DESC"
    lim, off = _page(p, 30)
    total = db.one(f"SELECT COUNT(*) c FROM reports{where}", a)["c"]
    rows = db.query(f"SELECT rid,kind,title,created,updated,severity,score,data FROM reports{where} ORDER BY {sort} LIMIT ? OFFSET ?",
                    a + [lim, off])
    items = []
    for r in rows:
        d = json.loads(r.pop("data"))
        r.update(summary=d.get("executive_summary", "")[:320], attack_types=d.get("attack_types", []),
                 industries=[x["name"] for x in d.get("industries", [])[:3]],
                 regions=[x["name"] for x in d.get("regions", [])[:3]],
                 n_iocs=len(d.get("iocs", [])), n_cves=len(d.get("cves", [])), n_articles=len(d.get("articles", [])))
        items.append(r)
    return {"total": total, "items": items}


def api_report(rid):
    r = db.one("SELECT * FROM reports WHERE rid=?", (rid,))
    if not r and rid.startswith("cve-"):
        c = db.one("SELECT * FROM cves WHERE cve_id=?", (rid[4:].upper(),))
        if c:
            title, sev, score, data = reports.cve_report_data(c)
            return {"rid": rid, "kind": "cve", "title": title, "severity": sev, "score": score,
                    "created": c["published"], "updated": c["updated"], **data}
    if not r:
        return None
    d = json.loads(r.pop("data"))
    d.update(r)
    return d


def api_patterns(p):
    where, args = article_where(p)
    arts = db.query(f"SELECT attack_types FROM articles{where}", args)
    c = Counter(t for a in arts for t in db.unj(a["attack_types"]))
    tech = Counter()
    out = []
    for k, v in ATTACK_PATTERNS.items():
        for _, _, tids in v["chain"]:
            for t in tids:
                tech[t] += c.get(k, 0)
        out.append({"key": k, "name": v["name"], "icon": v["icon"], "color": v["color"], "summary": v["summary"],
                    "count": c.get(k, 0), "chain": reports.build_chain([k]), "detection": v["detection"],
                    "mitigations": v["mitigations"], "queries": queries.behaviour_queries([k]).get(k, {}).get("queries", {})})
    out.sort(key=lambda x: -x["count"])
    techniques = [dict(reports.technique_info(t), count=n) for t, n in tech.most_common(40) if n]
    return {"patterns": out, "techniques": techniques}


def api_updates(p):
    since = p.get("since") or ""
    new_a = db.query("SELECT id,title,source,published,severity,url FROM articles WHERE fetched > ? ORDER BY published DESC LIMIT 15", (since,))
    return {"now": collectors.now_iso(),
            "articles": db.one("SELECT COUNT(*) c FROM articles WHERE fetched > ?", (since,))["c"],
            "iocs": db.one("SELECT COUNT(*) c FROM iocs WHERE last_seen > ?", (since,))["c"],
            "latest": new_a, "scheduler": scheduler.STATE}


def api_sources(p):
    rows = db.query("SELECT * FROM source_status ORDER BY kind, name")
    custom = {r["name"] for r in db.query("SELECT name FROM custom_feeds")}
    for r in rows:
        r["custom"] = r["name"] in custom
    return {"sources": rows, "scheduler": scheduler.STATE}


def api_query_builder(body):
    text = body.get("text", "")
    iocs = []
    for line in re.split(r"[\s,;]+", text):
        v = enrich.refang(line.strip().strip("'\""))
        if not v:
            continue
        if enrich.CVE_RE.fullmatch(v):
            continue
        iocs.append({"type": enrich.ioc_type(v), "value": v})
    cves = enrich.extract_cves(text)
    title = body.get("title") or "adhoc hunt"
    return {"iocs": iocs, "cves": cves, "siems": dict(queries.SIEMS),
            "ioc": queries.ioc_queries(iocs, title), "cve": queries.cve_queries(cves),
            "behaviour": queries.behaviour_queries(body.get("attack_types") or [])}


# ------------------------------------------------------------------ HTTP plumbing
class Handler(BaseHTTPRequestHandler):
    server_version = "ThreatPulse/1.0"

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(min(n, 2_000_000)))
        except ValueError:
            return {}

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        path = u.path
        try:
            routes = {"/api/meta": api_meta, "/api/stats": api_stats, "/api/articles": api_articles,
                      "/api/cves": api_cves, "/api/iocs": api_iocs, "/api/reports": api_reports,
                      "/api/patterns": api_patterns, "/api/updates": api_updates, "/api/sources": api_sources,
                      "/api/toolkit": lambda _: {"items": TOOLKIT}}
            if path in routes:
                return self._send(200, routes[path](p))
            if path == "/api/iocs/export":
                return self._send(200, api_iocs_export(p), "text/csv",
                                  {"Content-Disposition": "attachment; filename=iocs.csv"})
            m = re.fullmatch(r"/api/reports/([\w.\-]+)", path)
            if m:
                r = api_report(m.group(1))
                return self._send(200, r) if r else self._send(404, {"error": "not found"})
            return self._static(path)
        except Exception as e:  # noqa: BLE001
            log.exception("GET %s", path)
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        body = self._body()
        try:
            if path == "/api/collect":
                scheduler.run_async()
                return self._send(202, {"started": True, "scheduler": scheduler.STATE})
            if path == "/api/query-builder":
                return self._send(200, api_query_builder(body))
            if path == "/api/sources":
                name, url = (body.get("name") or "").strip(), (body.get("url") or "").strip()
                if not name or not url.startswith(("http://", "https://")):
                    return self._send(400, {"error": "name and http(s) url required"})
                db.write("INSERT OR REPLACE INTO custom_feeds VALUES(?,?)", (name, url))
                n = collectors.collect_rss(name, url)
                return self._send(200, {"added": name, "new_items": n})
            return self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            log.exception("POST %s", path)
            return self._send(500, {"error": str(e)})

    def do_DELETE(self):
        m = re.fullmatch(r"/api/sources/(.+)", urllib.parse.urlparse(self.path).path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            db.write("DELETE FROM custom_feeds WHERE name=?", (name,))
            db.write("DELETE FROM source_status WHERE name=?", (name,))
            return self._send(200, {"deleted": name})
        return self._send(404, {"error": "not found"})

    def _static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.normpath(os.path.join(config.WEB_DIR, path.lstrip("/")))
        if not full.startswith(config.WEB_DIR) or not os.path.isfile(full):
            full = os.path.join(config.WEB_DIR, "index.html")
        with open(full, "rb") as f:
            data = f.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, data, ctype)


def serve(host=None, port=None):
    httpd = ThreadingHTTPServer((host or config.HOST, port or config.PORT), Handler)
    log.info("ThreatPulse dashboard on http://%s:%s", host or config.HOST, port or config.PORT)
    httpd.serve_forever()

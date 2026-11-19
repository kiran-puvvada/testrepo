"""Threat report engine.

Correlates news, CVEs, IOCs and ATT&CK into detailed reports:
  * cve     - exploited / trending vulnerability reports
  * malware - malware family / campaign reports built from IOC feeds + news
  * actor   - threat-actor activity reports
  * trend   - attack-pattern trend reports (growth, industries, regions)
Every report carries attack chain, ATT&CK mapping, IOCs, CVEs, mitigations
and ready-to-run SIEM queries.
"""
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import db, queries
from .knowledge import ATTACK_PATTERNS, D3FEND_HINTS, GENERIC_PATTERN, TECHNIQUE_NAMES

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _now():
    return datetime.now(timezone.utc)


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def technique_info(tid):
    row = db.one("SELECT name, tactics, url FROM techniques WHERE tid=?", (tid,))
    if row:
        return {"id": tid, "name": row["name"], "tactics": db.unj(row["tactics"]), "url": row["url"]}
    if tid.startswith("AML."):
        return {"id": tid, "name": TECHNIQUE_NAMES.get(tid, tid), "tactics": [],
                "url": f"https://atlas.mitre.org/techniques/{tid}"}
    return {"id": tid, "name": TECHNIQUE_NAMES.get(tid, tid), "tactics": [],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


def build_chain(attack_types, context=None):
    """Return attack-flow stages merged from playbooks, personalised with context."""
    ctx = context or {}
    stages = []
    for at in (attack_types or [GENERIC_PATTERN])[:2]:
        p = ATTACK_PATTERNS.get(at)
        if not p:
            continue
        for stage, desc, tids in p["chain"]:
            if any(s["stage"] == stage for s in stages):
                continue
            d = desc
            if stage == "Initial Access" and ctx.get("product"):
                d = f"Exploit {ctx['product']}" + (f" ({ctx['cve']})" if ctx.get("cve") else "") + " — " + desc
            stages.append({"stage": stage, "description": d, "pattern": at,
                           "techniques": [technique_info(t) for t in tids],
                           "defend": D3FEND_HINTS.get(stage, [])})
    return stages


def pattern_block(attack_types):
    out = []
    for at in attack_types or []:
        p = ATTACK_PATTERNS.get(at)
        if p:
            out.append({"key": at, "name": p["name"], "icon": p["icon"], "color": p["color"],
                        "summary": p["summary"], "detection": p["detection"], "mitigations": p["mitigations"]})
    return out


def all_queries(iocs, cves, attack_types, title, products=None):
    return {
        "siems": dict(queries.SIEMS),
        "ioc": queries.ioc_queries(iocs, title),
        "cve": queries.cve_queries(cves, products),
        "behaviour": queries.behaviour_queries(attack_types),
    }


def _articles_matching(terms, since=None, limit=25):
    terms = [t for t in terms if t and len(t) > 2]
    if not terms:
        return []
    cond = " OR ".join(["title LIKE ? OR summary LIKE ? OR cves LIKE ? OR actors LIKE ?"] * len(terms))
    params = []
    for t in terms:
        params += [f"%{t}%"] * 4
    sql = f"SELECT * FROM articles WHERE ({cond})"
    if since:
        sql += " AND published >= ?"
        params.append(since)
    sql += " ORDER BY published DESC LIMIT ?"
    params.append(limit)
    return [_article_brief(a) for a in db.query(sql, params)]


def _article_brief(a):
    return {"id": a["id"], "title": a["title"], "url": a["url"], "source": a["source"], "published": a["published"],
            "severity": a["severity"], "summary": (a["summary"] or "")[:400]}


def _agg(articles_full, field, n=8):
    c = Counter()
    for a in articles_full:
        for v in db.unj(a[field]):
            c[v] += 1
    return [{"name": k, "count": v} for k, v in c.most_common(n)]


def _save(rid, kind, title, severity, score, data, created=None):
    prev = db.one("SELECT created FROM reports WHERE rid=?", (rid,))
    created = (prev or {}).get("created") or created or _iso(_now())
    data["generated"] = _iso(_now())
    db.write("""INSERT INTO reports(rid,kind,title,created,updated,severity,score,data) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(rid) DO UPDATE SET title=excluded.title, updated=excluded.updated, severity=excluded.severity,
                score=excluded.score, data=excluded.data""",
             (rid, kind, title, created, _iso(_now()), severity, score, json.dumps(data)))


# ---------------------------------------------------------------- CVE reports
def build_cve_reports(days=120):
    since = (_now() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = db.query("""SELECT * FROM cves WHERE (kev=1 AND kev_added >= ?)
                       OR (mentions >= 2) OR (cvss >= 9.0 AND mentions >= 1)
                       ORDER BY kev DESC, mentions DESC LIMIT 300""", (since,))
    n = 0
    for c in rows:
        title, sev, score, data = cve_report_data(c)
        _save(f"cve-{c['cve_id']}", "cve", title, sev, score, data, created=(c["kev_added"] or c["published"]))
        n += 1
    return n


def cve_report_data(c):
    """Build a full report for one CVE row (also used on-demand for any CVE)."""
    cid = c["cve_id"]
    arts_full = db.query("SELECT * FROM articles WHERE cves LIKE ? ORDER BY published DESC LIMIT 30", (f'%"{cid}"%',))
    arts = [_article_brief(a) for a in arts_full]
    text = " ".join(f"{a['title']} {a['summary']}" for a in arts_full) + " " + (c["description"] or "")
    ats = db.unj(c["attack_types"]) or []
    for a in arts_full:
        for t in db.unj(a["attack_types"]):
            if t not in ats:
                ats.append(t)
    if c["kev"] and "edge_exploitation" not in ats and re.search(
            r"(?i)vpn|firewall|gateway|appliance|server|remote code|rce|traversal|auth", text):
        ats.insert(0, "edge_exploitation")
    if (c["ransomware"] or "").lower() == "known" and "ransomware" not in ats:
        ats.append("ransomware")
    ats = ats[:3] or [GENERIC_PATTERN]
    iocs = []
    for a in arts_full:
        iocs += db.unj(a["iocs"])
    product = " ".join(x for x in [c["vendor"], c["product"]] if x)
    sev = "critical" if c["kev"] else (c["severity"] or "medium")
    if c["cvss"] and c["cvss"] > 0 and not c["kev"]:
        sev = c["severity"] or sev
    score = (50 if c["kev"] else 0) + (c["cvss"] or 0) * 3 + (c["epss"] or 0) * 30 + min(len(arts_full), 10) * 4
    title = f"{cid}: {product or 'Unknown product'}" + (" — actively exploited" if c["kev"] else "")
    cwe = [w for w in (c["cwe"] or "").split(",") if w]
    data = {
        "kind": "cve", "title": title,
        "executive_summary": _cve_summary(c, len(arts_full)),
        "cve": {k: c[k] for k in ("cve_id", "description", "vendor", "product", "cvss", "severity", "vector",
                                  "epss", "epss_pct", "kev", "kev_added", "kev_due", "ransomware",
                                  "required_action", "published")},
        "cwe": [{"id": w, "url": f"https://cwe.mitre.org/data/definitions/{w.split('-')[-1]}.html"} for w in cwe],
        "patterns": pattern_block(ats), "attack_types": ats,
        "chain": build_chain(ats, {"product": product, "cve": cid}),
        "industries": _agg(arts_full, "industries"), "regions": _agg(arts_full, "regions"),
        "actors": _agg(arts_full, "actors"),
        "articles": arts, "iocs": iocs[:200], "cves": [cid],
        "queries": all_queries(iocs, [cid], ats, title, [c["product"]]),
        "references": (db.unj(c["refs"]) or [])[:10] + [f"https://nvd.nist.gov/vuln/detail/{cid}",
                                                         f"https://www.cve.org/CVERecord?id={cid}"],
    }
    return title, sev, score, data


def _cve_summary(c, nart):
    s = f"{c['cve_id']} affects {c['vendor'] or 'the vendor'} {c['product'] or ''}".strip() + ". "
    if c["description"]:
        s += c["description"].strip().rstrip(".")[:600] + ". "
    if c["kev"]:
        s += f"CISA added it to the Known Exploited Vulnerabilities catalog on {c['kev_added']}, confirming in-the-wild exploitation"
        s += f"; federal remediation due {c['kev_due']}. " if c["kev_due"] else ". "
        if (c["ransomware"] or "").lower() == "known":
            s += "It is known to be used in ransomware campaigns. "
    if c["cvss"] and c["cvss"] > 0:
        s += f"CVSS base score {c['cvss']} ({c['severity']}). "
    if c["epss"] is not None:
        s += f"EPSS exploitation probability {c['epss']*100:.1f}% (percentile {c['epss_pct']*100:.0f}). "
    if nart:
        s += f"Referenced in {nart} news/research article(s)."
    return s


# ---------------------------------------------------------------- malware reports
def build_malware_reports(days=30):
    since = _iso(_now() - timedelta(days=days))
    fams = db.query("""SELECT malware, COUNT(*) c, MIN(first_seen) fs, MAX(last_seen) ls,
                       GROUP_CONCAT(DISTINCT source) srcs, GROUP_CONCAT(DISTINCT threat_type) tts
                       FROM iocs WHERE malware IS NOT NULL AND malware != '' AND first_seen >= ?
                       GROUP BY malware HAVING c >= 3 ORDER BY c DESC LIMIT 60""", (since,))
    n = 0
    for f in fams:
        name = f["malware"]
        iocs = db.query("""SELECT value,type,source,threat_type,first_seen,confidence,reference FROM iocs
                           WHERE malware=? ORDER BY first_seen DESC LIMIT 300""", (name,))
        short = re.sub(r"(?i)^(win|elf|osx|apk|js)\.", "", name).split(" ")[0]
        arts_full = db.query("SELECT * FROM articles WHERE title LIKE ? OR summary LIKE ? ORDER BY published DESC LIMIT 20",
                             (f"%{short}%", f"%{short}%")) if len(short) > 3 else []
        text = f"{name} {f['tts']} " + " ".join(a["title"] for a in arts_full)
        from .enrich import classify_attack
        ats = classify_attack(text)
        tts = (f["tts"] or "").lower()
        if not ats or ats == ["vulnerability"]:
            ats = ["botnet_ddos"] if "botnet" in tts else ["infostealer"] if "stealer" in text.lower() else ["phishing"] if "payload_delivery" in tts else ["botnet_ddos"]
        types = Counter(i["type"] for i in iocs)
        cves = sorted({c for a in arts_full for c in db.unj(a["cves"])})
        title = f"Malware campaign: {name}"
        score = f["c"] + len(arts_full) * 5
        sev = "high" if f["c"] > 50 or arts_full else "medium"
        data = {
            "kind": "malware", "title": title, "malware": name,
            "executive_summary": (f"{f['c']} indicators linked to {name} were observed between {(f['fs'] or '')[:10]} and "
                                  f"{(f['ls'] or '')[:10]} across {f['srcs']}. Threat types: {f['tts']}. "
                                  f"Activity matches the '{ATTACK_PATTERNS[ats[0]]['name']}' pattern. "
                                  + (f"{len(arts_full)} related news/research article(s) found." if arts_full else
                                     "No press coverage yet — IOC-driven detection.")),
            "ioc_breakdown": [{"name": k, "count": v} for k, v in types.most_common()],
            "patterns": pattern_block(ats), "attack_types": ats, "chain": build_chain(ats),
            "industries": _agg(arts_full, "industries"), "regions": _agg(arts_full, "regions"),
            "actors": _agg(arts_full, "actors"), "articles": [_article_brief(a) for a in arts_full],
            "iocs": iocs, "cves": cves,
            "queries": all_queries(iocs, cves, ats, title),
            "references": [f"https://threatfox.abuse.ch/browse/malware/{name.lower()}/",
                           f"https://malpedia.caad.fkie.fraunhofer.de/search?q={short}"],
        }
        _save(f"mal-{re.sub(r'[^a-z0-9]+', '-', name.lower())}", "malware", title, sev, score, data, created=f["fs"])
        n += 1
    return n


# ---------------------------------------------------------------- actor reports
def build_actor_reports(days=180):
    since = _iso(_now() - timedelta(days=days))
    c = Counter()
    for a in db.query("SELECT actors FROM articles WHERE published >= ? AND actors != '[]'", (since,)):
        for x in db.unj(a["actors"]):
            c[x] += 1
    n = 0
    for actor, cnt in c.most_common(40):
        if cnt < 2:
            break
        arts_full = db.query("SELECT * FROM articles WHERE actors LIKE ? ORDER BY published DESC LIMIT 40", (f'%"{actor}"%',))
        ats = [x["name"] for x in _agg(arts_full, "attack_types", 3)] or ["apt_espionage"]
        iocs, cves = [], set()
        for a in arts_full:
            iocs += db.unj(a["iocs"])
            cves.update(db.unj(a["cves"]))
        cves = sorted(cves)
        title = f"Threat actor: {actor}"
        data = {
            "kind": "actor", "title": title, "actor": actor,
            "executive_summary": (f"{actor} was referenced in {cnt} reports over the last {days} days. Most associated "
                                  f"activity: {', '.join(ATTACK_PATTERNS[a]['name'] for a in ats if a in ATTACK_PATTERNS)}. "
                                  + (f"Exploited CVEs: {', '.join(cves[:8])}. " if cves else "")
                                  + "See the attack chain for the typical intrusion flow and hunt queries below."),
            "patterns": pattern_block(ats), "attack_types": ats, "chain": build_chain(ats),
            "industries": _agg(arts_full, "industries"), "regions": _agg(arts_full, "regions"),
            "actors": [{"name": actor, "count": cnt}], "articles": [_article_brief(a) for a in arts_full],
            "iocs": iocs[:200], "cves": cves,
            "queries": all_queries(iocs, cves, ats, title),
            "references": [f"https://attack.mitre.org/groups/?q={actor}", f"https://malpedia.caad.fkie.fraunhofer.de/search?q={actor}"],
        }
        sev = "high" if "apt_espionage" in ats or "ransomware" in ats else "medium"
        _save(f"actor-{re.sub(r'[^a-z0-9]+', '-', actor.lower())}", "actor", title, sev, cnt * 6 + len(cves) * 5, data,
              created=arts_full[-1]["published"] if arts_full else None)
        n += 1
    return n


# ---------------------------------------------------------------- trend reports
def build_trend_reports(window=7):
    now = _now()
    cur_start, prev_start = _iso(now - timedelta(days=window)), _iso(now - timedelta(days=window * 2))
    n = 0
    for at, p in ATTACK_PATTERNS.items():
        like = f'%"{at}"%'
        cur = db.query("SELECT * FROM articles WHERE attack_types LIKE ? AND published >= ? ORDER BY published DESC", (like, cur_start))
        prev = db.one("SELECT COUNT(*) c FROM articles WHERE attack_types LIKE ? AND published >= ? AND published < ?",
                      (like, prev_start, cur_start))["c"]
        if not cur:
            continue
        growth = ((len(cur) - prev) / prev * 100) if prev else 100.0
        iocs, cves = [], Counter()
        for a in cur:
            iocs += db.unj(a["iocs"])
            cves.update(db.unj(a["cves"]))
        top_cves = [k for k, _ in cves.most_common(15)]
        cve_rows = db.query(f"SELECT cve_id,vendor,product,cvss,kev,epss FROM cves WHERE cve_id IN ({','.join('?' * len(top_cves))})",
                            top_cves) if top_cves else []
        title = f"Trend: {p['name']} — last {window} days"
        data = {
            "kind": "trend", "title": title, "pattern_key": at,
            "executive_summary": (f"{len(cur)} reports on {p['name'].lower()} in the last {window} days "
                                  f"({'+' if growth >= 0 else ''}{growth:.0f}% vs previous {window} days). {p['summary']}"),
            "stats": {"current": len(cur), "previous": prev, "growth": round(growth, 1)},
            "patterns": pattern_block([at]), "attack_types": [at], "chain": build_chain([at]),
            "industries": _agg(cur, "industries"), "regions": _agg(cur, "regions"), "actors": _agg(cur, "actors"),
            "articles": [_article_brief(a) for a in cur[:30]], "iocs": iocs[:200], "cves": top_cves,
            "cve_details": cve_rows,
            "queries": all_queries(iocs, top_cves, [at], title),
            "references": [],
        }
        sev = max((a["severity"] for a in cur), key=lambda s: SEV_RANK.get(s, 0))
        _save(f"trend-{at}", "trend", title, sev, len(cur) * 3 + max(growth, 0) / 10, data)
        n += 1
    return n


def rebuild_all():
    return {"cve": build_cve_reports(), "malware": build_malware_reports(),
            "actor": build_actor_reports(), "trend": build_trend_reports()}

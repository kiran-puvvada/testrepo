"""Source collectors. Each returns (count_new_or_updated, message)."""
import csv
import gzip
import hashlib
import io
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from . import config, db, enrich

log = logging.getLogger("collectors")


# ---------------------------------------------------------------- helpers
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url, data=None, headers=None, timeout=None):
    h = {"User-Agent": config.USER_AGENT, "Accept-Encoding": "gzip", "Accept": "*/*"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=timeout or config.HTTP_TIMEOUT) as r:
        raw = r.read()
        if r.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return raw


def fetch_json(url, **kw):
    return json.loads(fetch(url, **kw).decode("utf-8", "replace"))


def fetch_first(urls, parser=fetch_json):
    err = None
    for u in urls:
        try:
            return parser(u), u
        except Exception as e:  # noqa: BLE001 - try mirrors
            err = e
            log.info("source %s failed: %s", u, e)
    raise err


def norm_date(s):
    """Parse RSS / ISO / plain dates into ISO-8601 UTC."""
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        d = None
    if d is None:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S UTC"):
            try:
                d = datetime.strptime(s.replace("+00:00", "Z") if fmt.endswith("Z") else s, fmt)
                break
            except ValueError:
                continue
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_status(name, kind, url, ok, items, message=""):
    total = {
        "news": "SELECT COUNT(*) c FROM articles WHERE source=?",
        "ioc": "SELECT COUNT(*) c FROM iocs WHERE source=?",
    }.get(kind)
    tot = db.one(total, (name,))["c"] if total else items
    prev = db.one("SELECT last_ok FROM source_status WHERE name=?", (name,)) or {}
    db.write("""INSERT INTO source_status(name,kind,url,last_run,last_ok,items,total,status,message)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,url=excluded.url,last_run=excluded.last_run,
                last_ok=excluded.last_ok,items=excluded.items,total=excluded.total,status=excluded.status,
                message=excluded.message""",
             (name, kind, url, now_iso(), now_iso() if ok else prev.get("last_ok"), items, tot,
              "ok" if ok else "error", message[:300]))


# ---------------------------------------------------------------- news / RSS
NS = {"atom": "http://www.w3.org/2005/Atom", "content": "http://purl.org/rss/1.0/modules/content/",
      "dc": "http://purl.org/dc/elements/1.1/"}


def parse_feed(raw):
    root = ET.fromstring(raw)
    items = []
    if root.tag.endswith("rss") or root.find("channel") is not None:
        for it in root.iter("item"):
            content = it.findtext("content:encoded", namespaces=NS) or ""
            items.append({
                "title": it.findtext("title") or "",
                "url": (it.findtext("link") or "").strip(),
                "summary": it.findtext("description") or "",
                "content": content,
                "published": it.findtext("pubDate") or it.findtext("dc:date", namespaces=NS),
                "guid": it.findtext("guid"),
            })
    else:  # Atom
        for e in root.findall("atom:entry", NS):
            link = e.find("atom:link[@rel='alternate']", NS)
            if link is None:
                link = e.find("atom:link", NS)
            items.append({
                "title": e.findtext("atom:title", default="", namespaces=NS),
                "url": link.get("href") if link is not None else "",
                "summary": e.findtext("atom:summary", default="", namespaces=NS),
                "content": e.findtext("atom:content", default="", namespaces=NS),
                "published": e.findtext("atom:published", namespaces=NS) or e.findtext("atom:updated", namespaces=NS),
                "guid": e.findtext("atom:id", namespaces=NS),
            })
    return items


def store_article(source, title, url, summary, published, content="", uid=None):
    title = enrich.clean_text(title)
    summary_txt = enrich.clean_text(summary)
    full = f"{title}\n{summary_txt}\n{enrich.clean_text(content)}"
    uid = uid or hashlib.sha1((url or title).encode()).hexdigest()
    cves = enrich.extract_cves(full)
    kev_hit = bool(cves) and bool(db.one(
        f"SELECT 1 x FROM cves WHERE kev=1 AND cve_id IN ({','.join('?' * len(cves))})", cves))
    row = (uid, source, title, url, summary_txt[:1200], norm_date(published) or now_iso(), now_iso(),
           db.j(enrich.classify_attack(full)), db.j(enrich.classify_industries(full)),
           db.j(enrich.classify_regions(full)), db.j(cves), db.j(enrich.extract_iocs(full)),
           db.j(enrich.extract_actors(full)), enrich.severity_for(full, cves, kev_hit))
    cur = db.write("""INSERT OR IGNORE INTO articles(uid,source,title,url,summary,published,fetched,
                      attack_types,industries,regions,cves,iocs,actors,severity)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)
    if cur.rowcount:
        for c in cves:  # make sure CVEs mentioned in news exist & count mentions
            db.write("INSERT OR IGNORE INTO cves(cve_id, sources) VALUES(?, ?)", (c, db.j(["news"])))
            db.write("UPDATE cves SET mentions = COALESCE(mentions,0)+1 WHERE cve_id=?", (c,))
    return cur.rowcount


def collect_rss(name, url):
    try:
        items = parse_feed(fetch(url))
        n = sum(store_article(name, i["title"], i["url"], i["summary"], i["published"], i["content"],
                              uid=None) for i in items if i["title"])
        set_status(name, "news", url, True, n, f"{len(items)} items in feed, {n} new")
        return n
    except Exception as e:  # noqa: BLE001
        set_status(name, "news", url, False, 0, f"{type(e).__name__}: {e}")
        return 0


# ---------------------------------------------------------------- CISA KEV
def collect_kev():
    try:
        data, used = fetch_first(config.KEV_URLS)
        rows = []
        for v in data.get("vulnerabilities", []):
            text = f"{v.get('vulnerabilityName','')} {v.get('shortDescription','')} {v.get('product','')}"
            rows.append((v["cveID"], v.get("shortDescription"), v.get("vendorProject"), v.get("product"),
                         v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
                         v.get("requiredAction"), v.get("dateAdded"), ",".join(v.get("cwes") or []) or None,
                         db.j(enrich.classify_attack(text + " actively exploited")), v.get("vulnerabilityName")))
        db.write_many("""INSERT INTO cves(cve_id,description,vendor,product,kev,kev_added,kev_due,ransomware,
                         required_action,published,cwe,attack_types,sources)
                         VALUES(?,?,?,?,1,?,?,?,?,?,?,?,'["CISA KEV"]')
                         ON CONFLICT(cve_id) DO UPDATE SET kev=1,kev_added=excluded.kev_added,kev_due=excluded.kev_due,
                         ransomware=excluded.ransomware,required_action=excluded.required_action,
                         vendor=COALESCE(cves.vendor,excluded.vendor),product=COALESCE(cves.product,excluded.product),
                         description=COALESCE(cves.description,excluded.description),
                         published=COALESCE(cves.published,excluded.published),
                         cwe=COALESCE(cves.cwe,excluded.cwe),attack_types=excluded.attack_types""",
                      [r[:11] for r in rows])
        set_status("CISA KEV", "vuln", used, True, len(rows), f"{len(rows)} known exploited CVEs")
        return len(rows)
    except Exception as e:  # noqa: BLE001
        set_status("CISA KEV", "vuln", config.KEV_URLS[0], False, 0, str(e))
        return 0


# ---------------------------------------------------------------- NVD / CVE List
def _upsert_cve(cid, desc, vendor, product, cvss, vector, cwe, published, updated, refs, src):
    text = f"{desc} {vendor} {product}"
    db.write("""INSERT INTO cves(cve_id,description,vendor,product,cvss,severity,vector,cwe,published,updated,refs,
                attack_types,sources) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET description=COALESCE(excluded.description,cves.description),
                vendor=COALESCE(cves.vendor,excluded.vendor),product=COALESCE(cves.product,excluded.product),
                cvss=COALESCE(excluded.cvss,cves.cvss),severity=COALESCE(excluded.severity,cves.severity),
                vector=COALESCE(excluded.vector,cves.vector),cwe=COALESCE(cves.cwe,excluded.cwe),
                published=COALESCE(cves.published,excluded.published),updated=excluded.updated,
                refs=excluded.refs,attack_types=CASE WHEN cves.kev=1 THEN cves.attack_types ELSE excluded.attack_types END""",
             (cid, desc, vendor, product, cvss, enrich.cvss_severity(cvss) if cvss is not None else None, vector,
              cwe, published, updated, db.j(refs[:15]), db.j(enrich.classify_attack(text) or ["vulnerability"]),
              db.j([src])))


def collect_nvd(hours=48):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
              "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": 500}
    url = config.NVD_URL + "?" + urllib.parse.urlencode(params)
    try:
        hdr = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        data = fetch_json(url, headers=hdr)
        n = 0
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            cvss = vector = None
            for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if c.get("metrics", {}).get(k):
                    m = c["metrics"][k][0]["cvssData"]
                    cvss, vector = m.get("baseScore"), m.get("vectorString")
                    break
            cwe = ",".join(d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                           if d["value"].startswith("CWE"))
            vendor = product = None
            for conf in c.get("configurations", []):
                for node in conf.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 4:
                            vendor, product = parts[3], parts[4]
                            break
            refs = [r["url"] for r in c.get("references", [])]
            _upsert_cve(c["id"], desc, vendor, product, cvss, vector, cwe or None,
                        norm_date(c.get("published")), norm_date(c.get("lastModified")), refs, "NVD")
            n += 1
        set_status("NVD", "vuln", config.NVD_URL, True, n, f"{n} CVEs published in last {hours}h")
        return n
    except Exception as e:  # noqa: BLE001
        set_status("NVD", "vuln", config.NVD_URL, False, 0, str(e))
        return 0


def parse_cve_record(rec):
    meta = rec.get("cveMetadata", {})
    cna = rec.get("containers", {}).get("cna", {})
    adps = rec.get("containers", {}).get("adp", [])
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    aff = (cna.get("affected") or [{}])[0]
    cvss = vector = None
    for m in cna.get("metrics", []) + [m for a in adps for m in a.get("metrics", [])]:
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if k in m:
                cvss, vector = m[k].get("baseScore"), m[k].get("vectorString")
                break
        if cvss is not None:
            break
    cwes = [d.get("cweId") for p in cna.get("problemTypes", []) for d in p.get("descriptions", []) if d.get("cweId")]
    refs = [r["url"] for r in cna.get("references", [])]
    return dict(cid=meta.get("cveId"), desc=desc, vendor=aff.get("vendor"), product=aff.get("product"),
                cvss=cvss, vector=vector, cwe=",".join(cwes) or None, published=norm_date(meta.get("datePublished")),
                updated=norm_date(meta.get("dateUpdated")), refs=refs, state=meta.get("state"))


def collect_cvelist():
    """CVE Program's official GitHub mirror - works where NVD API is slow/blocked."""
    try:
        delta = fetch_json(config.CVELIST_DELTA_URL)
        links, seen = [], set()
        for d in delta:
            for e in d.get("new", []) + d.get("updated", []):
                if e["cveId"] not in seen:
                    seen.add(e["cveId"])
                    links.append(e)
        have = {r["cve_id"] for r in db.query("SELECT cve_id FROM cves WHERE description IS NOT NULL")}
        todo = [e for e in links if e["cveId"] not in have][: config.CVELIST_MAX]
        n = 0
        for e in todo:
            try:
                p = parse_cve_record(fetch_json(e["githubLink"]))
                if p["state"] != "PUBLISHED" or not p["desc"]:
                    continue
                _upsert_cve(p["cid"], p["desc"], p["vendor"], p["product"], p["cvss"], p["vector"], p["cwe"],
                            p["published"], p["updated"], p["refs"], "CVE List")
                n += 1
            except Exception as ex:  # noqa: BLE001
                log.debug("cve %s failed: %s", e["cveId"], ex)
        set_status("CVE List (cve.org)", "vuln", config.CVELIST_DELTA_URL, True, n,
                   f"{len(links)} changed CVEs in delta log, {n} imported")
        return n
    except Exception as e:  # noqa: BLE001
        set_status("CVE List (cve.org)", "vuln", config.CVELIST_DELTA_URL, False, 0, str(e))
        return 0


def enrich_cves_from_cvelist(limit=80):
    """Fill missing CVSS/description for KEV + news CVEs from cvelistV5."""
    rows = db.query("""SELECT cve_id FROM cves WHERE (cvss IS NULL OR description IS NULL)
                       ORDER BY kev DESC, mentions DESC, kev_added DESC LIMIT ?""", (limit,))
    n = 0
    for r in rows:
        cid = r["cve_id"]
        try:
            _, year, num = cid.split("-")
            bucket = num[:-3] + "xxx"
            url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cid}.json"
            p = parse_cve_record(fetch_json(url))
            db.write("""UPDATE cves SET description=COALESCE(description,?), cvss=COALESCE(cvss,?),
                        severity=COALESCE(severity,?), vector=COALESCE(vector,?), cwe=COALESCE(cwe,?),
                        vendor=COALESCE(vendor,?), product=COALESCE(product,?), published=COALESCE(published,?),
                        refs=CASE WHEN refs IS NULL OR refs='[]' THEN ? ELSE refs END WHERE cve_id=?""",
                     (p["desc"] or None, p["cvss"], enrich.cvss_severity(p["cvss"]) if p["cvss"] is not None else None,
                      p["vector"], p["cwe"], p["vendor"], p["product"], p["published"], db.j(p["refs"][:15]), cid))
            n += 1
        except Exception:  # noqa: BLE001
            # mark as attempted so we don't retry forever
            db.write("UPDATE cves SET cvss=COALESCE(cvss,-1) WHERE cve_id=?", (cid,))
    return n


def collect_epss():
    rows = db.query("""SELECT cve_id FROM cves WHERE epss IS NULL ORDER BY kev DESC, published DESC LIMIT 300""")
    if not rows:
        return 0
    n = 0
    try:
        for i in range(0, len(rows), 100):
            ids = ",".join(r["cve_id"] for r in rows[i:i + 100])
            data = fetch_json(f"{config.EPSS_URL}?cve={ids}")
            for d in data.get("data", []):
                db.write("UPDATE cves SET epss=?, epss_pct=? WHERE cve_id=?",
                         (float(d["epss"]), float(d["percentile"]), d["cve"]))
                n += 1
        set_status("FIRST EPSS", "vuln", config.EPSS_URL, True, n, f"EPSS scores for {n} CVEs")
    except Exception as e:  # noqa: BLE001
        set_status("FIRST EPSS", "vuln", config.EPSS_URL, False, 0, str(e))
    return n


# ---------------------------------------------------------------- IOC feeds
def _store_iocs(source, rows):
    return db.write_many("""INSERT INTO iocs(value,type,source,malware,threat_type,confidence,tags,first_seen,last_seen,reference)
                            VALUES(?,?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(value,source) DO UPDATE SET last_seen=excluded.last_seen""", rows)


def collect_threatfox():
    if not config.ABUSECH_AUTH_KEY:
        set_status("ThreatFox", "ioc", config.THREATFOX_URL, False, 0,
                   "Set ABUSECH_AUTH_KEY (free at auth.abuse.ch) to enable")
        return 0
    try:
        data = fetch_json(config.THREATFOX_URL, data=json.dumps({"query": "get_iocs", "days": 3}).encode(),
                          headers={"Auth-Key": config.ABUSECH_AUTH_KEY, "Content-Type": "application/json"})
        rows = []
        for i in data.get("data") or []:
            t = {"ip:port": "ip", "domain": "domain", "url": "url", "md5_hash": "md5", "sha256_hash": "sha256",
                 "sha1_hash": "sha1"}.get(i.get("ioc_type"), i.get("ioc_type"))
            rows.append((i["ioc"], t, "ThreatFox", i.get("malware_printable"), i.get("threat_type"),
                         i.get("confidence_level"), db.j(i.get("tags")), norm_date(i.get("first_seen")),
                         norm_date(i.get("last_seen") or i.get("first_seen")),
                         f"https://threatfox.abuse.ch/ioc/{i.get('id')}/"))
        n = _store_iocs("ThreatFox", rows)
        set_status("ThreatFox", "ioc", config.THREATFOX_URL, True, len(rows), f"{len(rows)} IOCs (3 days)")
        return n
    except Exception as e:  # noqa: BLE001
        set_status("ThreatFox", "ioc", config.THREATFOX_URL, False, 0, str(e))
        return 0


def collect_urlhaus():
    try:
        hdr = {"Auth-Key": config.ABUSECH_AUTH_KEY} if config.ABUSECH_AUTH_KEY else {}
        text = fetch(config.URLHAUS_CSV_URL, headers=hdr).decode("utf-8", "replace")
        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        rows = []
        for r in csv.reader(io.StringIO("\n".join(lines))):
            if len(r) < 8:
                continue
            # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            tags = [t for t in r[6].split(",") if t]
            malware = next((t for t in tags if t.lower() not in ("exe", "elf", "32-bit", "64-bit", "arm", "mips", "x86", "sh", "dll", "zip", "ua-wget", "mozi")), None)
            rows.append((r[2], "url", "URLhaus", malware, r[5], 80, db.j(tags), norm_date(r[1]),
                         norm_date(r[4] or r[1]), r[7]))
        rows = rows[:3000]
        _store_iocs("URLhaus", rows)
        set_status("URLhaus", "ioc", config.URLHAUS_CSV_URL, True, len(rows), f"{len(rows)} recent malware URLs")
        return len(rows)
    except Exception as e:  # noqa: BLE001
        set_status("URLhaus", "ioc", config.URLHAUS_CSV_URL, False, 0, str(e))
        return 0


def collect_feodo():
    try:
        data = fetch_json(config.FEODO_URL)
        rows = [(d["ip_address"], "ip", "Feodo Tracker", d.get("malware"), "botnet_cc", 90,
                 db.j([f"port:{d.get('port')}", d.get("country") or ""]), norm_date(d.get("first_seen")),
                 norm_date(d.get("last_online") or d.get("first_seen")),
                 f"https://feodotracker.abuse.ch/browse/host/{d['ip_address']}/") for d in data]
        _store_iocs("Feodo Tracker", rows)
        set_status("Feodo Tracker", "ioc", config.FEODO_URL, True, len(rows), f"{len(rows)} botnet C2 IPs")
        return len(rows)
    except Exception as e:  # noqa: BLE001
        set_status("Feodo Tracker", "ioc", config.FEODO_URL, False, 0, str(e))
        return 0


def collect_otx():
    if not config.OTX_API_KEY:
        set_status("AlienVault OTX", "ioc", config.OTX_URL, False, 0, "Set OTX_API_KEY (free) to enable")
        return 0
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
        data = fetch_json(f"{config.OTX_URL}?limit=50&modified_since={since}",
                          headers={"X-OTX-API-KEY": config.OTX_API_KEY})
        n = 0
        for p in data.get("results", []):
            text = f"{p.get('name')} {p.get('description')} {' '.join(p.get('tags', []))} " \
                   f"{' '.join(p.get('industries', []))} {' '.join(p.get('targeted_countries', []))}"
            store_article("AlienVault OTX", p.get("name"), f"https://otx.alienvault.com/pulse/{p['id']}",
                          (p.get("description") or "") + " " + text, p.get("created"), uid="otx-" + p["id"])
            rows = []
            for ind in p.get("indicators", [])[:500]:
                t = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
                     "FileHash-SHA256": "sha256", "FileHash-MD5": "md5", "FileHash-SHA1": "sha1"}.get(ind["type"])
                if t:
                    rows.append((ind["indicator"], t, "AlienVault OTX",
                                 (p.get("malware_families") or [{}])[0].get("display_name") if p.get("malware_families") else p.get("name")[:60],
                                 p.get("adversary") or "pulse", 70, db.j(p.get("tags", [])[:8]),
                                 norm_date(ind.get("created")), norm_date(p.get("modified")),
                                 f"https://otx.alienvault.com/pulse/{p['id']}"))
            n += _store_iocs("AlienVault OTX", rows) or 0
        set_status("AlienVault OTX", "ioc", config.OTX_URL, True, n, f"{len(data.get('results', []))} pulses")
        return n
    except Exception as e:  # noqa: BLE001
        set_status("AlienVault OTX", "ioc", config.OTX_URL, False, 0, str(e))
        return 0


def harvest_article_iocs():
    """IOCs extracted from news/research articles become a searchable IOC source too."""
    rows = []
    for a in db.query("SELECT source,title,url,published,iocs,attack_types FROM articles WHERE iocs != '[]' "
                      "ORDER BY published DESC LIMIT 2000"):
        for i in db.unj(a["iocs"]):
            rows.append((i["value"], i["type"], "News: " + a["source"], None,
                         (db.unj(a["attack_types"]) or ["report"])[0], 50, db.j([]), a["published"],
                         a["published"], a["url"]))
    if rows:
        _store_iocs("news", rows)
    return len(rows)


# ---------------------------------------------------------------- MITRE ATT&CK
def collect_mitre():
    if db.one("SELECT COUNT(*) c FROM techniques")["c"] > 100:
        last = db.one("SELECT last_ok FROM source_status WHERE name='MITRE ATT&CK'")
        if last and last["last_ok"] and last["last_ok"] > (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d"):
            return 0  # weekly is plenty
    try:
        data = fetch_json(config.MITRE_ATTACK_URL, timeout=120)
        rows = []
        for o in data.get("objects", []):
            if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if not ext:
                continue
            tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
            rows.append((ext["external_id"], o.get("name"), db.j(tactics), (o.get("description") or "")[:1500], ext.get("url")))
        db.write_many("INSERT OR REPLACE INTO techniques VALUES(?,?,?,?,?)", rows)
        set_status("MITRE ATT&CK", "framework", config.MITRE_ATTACK_URL, True, len(rows), f"{len(rows)} techniques")
        return len(rows)
    except Exception as e:  # noqa: BLE001
        set_status("MITRE ATT&CK", "framework", config.MITRE_ATTACK_URL, False, 0, str(e))
        return 0


def all_rss_feeds():
    feeds = list(config.RSS_FEEDS)
    feeds += [(r["name"], r["url"]) for r in db.query("SELECT name,url FROM custom_feeds")]
    return feeds

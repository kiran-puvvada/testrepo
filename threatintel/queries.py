"""Generate ready-to-run hunt queries for Google SecOps (UDM search + YARA-L 2.0),
Splunk SPL, Microsoft Sentinel KQL, Elastic (KQL / ES|QL) and IBM QRadar AQL."""
import re

from .knowledge import ATTACK_PATTERNS

SIEMS = [
    ("secops", "Google SecOps (UDM Search)"),
    ("yaral", "Google SecOps (YARA-L 2.0 rule)"),
    ("splunk", "Splunk SPL"),
    ("sentinel", "Microsoft Sentinel / Defender KQL"),
    ("elastic", "Elastic (KQL / ES|QL)"),
    ("qradar", "IBM QRadar AQL"),
]

MAX_PER_TYPE = 50


def _q(v):
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sq(v):
    return "'" + v.replace("'", "''") + "'"


def _rule_name(title):
    s = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
    return ("ti_" + s)[:60]


def group_iocs(iocs):
    g = {"ip": [], "domain": [], "url": [], "sha256": [], "sha1": [], "md5": []}
    for i in iocs:
        t, v = i["type"], i["value"]
        if t == "ip":
            v = v.split(":")[0]
        if t in g and v not in g[t] and len(g[t]) < MAX_PER_TYPE:
            g[t].append(v)
    return g


# ------------------------------------------------------------------ IOC queries
def ioc_queries(iocs, title="threat report"):
    g = group_iocs(iocs)
    if not any(g.values()):
        return {}
    out = {}

    # --- Google SecOps UDM search
    parts = []
    if g["ip"]:
        ips = " OR ".join(f'target.ip = {_q(i)} OR principal.ip = {_q(i)}' for i in g["ip"])
        parts.append(f"({ips})")
    if g["domain"]:
        ds = " OR ".join(f'network.dns.questions.name = {_q(d)} OR target.hostname = {_q(d)}' for d in g["domain"])
        parts.append(f"({ds})")
    if g["url"]:
        parts.append("(" + " OR ".join(f"target.url = {_q(u)}" for u in g["url"]) + ")")
    for h in ("sha256", "sha1", "md5"):
        if g[h]:
            parts.append("(" + " OR ".join(f"target.file.{h} = {_q(x)}" for x in g[h]) + ")")
    out["secops"] = "\nOR\n".join(parts)

    # --- YARA-L 2.0 rule
    conds = []
    if g["ip"]:
        conds.append("    " + "\n    or ".join(f"$e.target.ip = {_q(i)}" for i in g["ip"]))
    if g["domain"]:
        conds.append("    " + "\n    or ".join(f"$e.network.dns.questions.name = {_q(d)}" for d in g["domain"]))
    if g["url"]:
        conds.append("    " + "\n    or ".join(f"$e.target.url = {_q(u)}" for u in g["url"]))
    for h in ("sha256", "sha1", "md5"):
        if g[h]:
            conds.append("    " + "\n    or ".join(f"$e.target.file.{h} = {_q(x)}" for x in g[h]))
    out["yaral"] = (
        f"rule {_rule_name(title)} {{\n"
        f"  meta:\n"
        f"    author = \"ThreatPulse\"\n"
        f"    description = {_q('IOC match: ' + title)}\n"
        f"    severity = \"HIGH\"\n"
        f"    tactic = \"TA0011\"\n\n"
        f"  events:\n"
        f"    (\n" + "\n    or\n".join(conds) + "\n    )\n"
        f"    $e.principal.hostname = $host\n\n"
        f"  match:\n"
        f"    $host over 1h\n\n"
        f"  condition:\n"
        f"    $e\n}}\n"
        f"// Tip: for large lists, store IOCs in a reference list and use e.g. $e.target.ip in %ti_ips"
    )

    # --- Splunk
    sp = []
    if g["ip"]:
        lst = ",".join(_q(i) for i in g["ip"])
        sp.append(f"dest_ip IN ({lst}) OR src_ip IN ({lst}) OR dest IN ({lst})")
    if g["domain"]:
        lst = ",".join(_q(d) for d in g["domain"])
        sp.append(f"query IN ({lst}) OR dest_host IN ({lst}) OR url_domain IN ({lst})")
    if g["url"]:
        sp.append("url IN (" + ",".join(_q(u) for u in g["url"]) + ")")
    hashes = g["sha256"] + g["sha1"] + g["md5"]
    if hashes:
        lst = ",".join(_q(h) for h in hashes)
        sp.append(f"file_hash IN ({lst}) OR sha256 IN ({lst}) OR md5 IN ({lst}) OR Hashes IN ({lst})")
    out["splunk"] = ("index=* earliest=-30d (" + " OR ".join(f"({s})" for s in sp) + ")\n"
                     "| stats count min(_time) as first_seen max(_time) as last_seen values(sourcetype) as sourcetypes by host, src_ip, dest_ip, user\n"
                     "| convert ctime(first_seen) ctime(last_seen)")

    # --- Sentinel / Defender KQL
    kq = []
    if g["ip"]:
        kq.append("let ti_ips = dynamic([" + ",".join(_q(i) for i in g["ip"]) + "]);")
    if g["domain"]:
        kq.append("let ti_domains = dynamic([" + ",".join(_q(d) for d in g["domain"]) + "]);")
    if g["url"]:
        kq.append("let ti_urls = dynamic([" + ",".join(_q(u) for u in g["url"]) + "]);")
    if hashes:
        kq.append("let ti_hashes = dynamic([" + ",".join(_q(h) for h in hashes) + "]);")
    body = []
    if g["ip"]:
        body.append("(DeviceNetworkEvents | where RemoteIP in (ti_ips) | project TimeGenerated, DeviceName, Indicator=RemoteIP, Table=\"DeviceNetworkEvents\"),\n"
                    "(CommonSecurityLog | where DestinationIP in (ti_ips) or SourceIP in (ti_ips) | project TimeGenerated, DeviceName=Computer, Indicator=coalesce(DestinationIP, SourceIP), Table=\"CommonSecurityLog\"),\n"
                    "(SigninLogs | where IPAddress in (ti_ips) | project TimeGenerated, DeviceName=UserPrincipalName, Indicator=IPAddress, Table=\"SigninLogs\")")
    if g["domain"]:
        body.append("(DeviceNetworkEvents | where RemoteUrl has_any (ti_domains) | project TimeGenerated, DeviceName, Indicator=RemoteUrl, Table=\"DeviceNetworkEvents\"),\n"
                    "(DnsEvents | where Name in~ (ti_domains) | project TimeGenerated, DeviceName=Computer, Indicator=Name, Table=\"DnsEvents\")")
    if g["url"]:
        body.append("(DeviceNetworkEvents | where RemoteUrl in~ (ti_urls) | project TimeGenerated, DeviceName, Indicator=RemoteUrl, Table=\"DeviceNetworkEvents\")")
    if hashes:
        body.append("(DeviceFileEvents | where SHA256 in~ (ti_hashes) or SHA1 in~ (ti_hashes) or MD5 in~ (ti_hashes) | project TimeGenerated, DeviceName, Indicator=coalesce(SHA256, SHA1, MD5), Table=\"DeviceFileEvents\")")
    out["sentinel"] = "\n".join(kq) + "\nunion isfuzzy=true\n" + ",\n".join(body) + "\n| where TimeGenerated > ago(30d)\n| summarize Hits=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Indicator, DeviceName, Table"

    # --- Elastic
    el = []
    if g["ip"]:
        lst = " or ".join(_q(i) for i in g["ip"])
        el.append(f"destination.ip : ({lst}) or source.ip : ({lst})")
    if g["domain"]:
        lst = " or ".join(_q(d) for d in g["domain"])
        el.append(f"dns.question.name : ({lst}) or url.domain : ({lst})")
    if g["url"]:
        el.append("url.full : (" + " or ".join(_q(u) for u in g["url"]) + ")")
    if hashes:
        lst = " or ".join(_q(h) for h in hashes)
        el.append(f"file.hash.sha256 : ({lst}) or file.hash.md5 : ({lst}) or file.hash.sha1 : ({lst})")
    esql_cond = []
    if g["ip"]:
        esql_cond.append("TO_STRING(destination.ip) IN (" + ", ".join(_q(i) for i in g["ip"]) + ")")
    if g["domain"]:
        esql_cond.append("dns.question.name IN (" + ", ".join(_q(d) for d in g["domain"]) + ")")
    if hashes:
        esql_cond.append("file.hash.sha256 IN (" + ", ".join(_q(h) for h in hashes) + ")")
    out["elastic"] = ("// KQL (Discover / detection rule)\n" + " or\n".join(f"({e})" for e in el) +
                      ("\n\n// ES|QL\nFROM logs-*\n| WHERE " + " OR ".join(esql_cond) +
                       "\n| STATS hits = COUNT(*) BY host.name, source.ip" if esql_cond else ""))

    # --- QRadar AQL
    aq = []
    if g["ip"]:
        lst = ",".join(_sq(i) for i in g["ip"])
        aq.append(f"destinationip IN ({lst}) OR sourceip IN ({lst})")
    if g["domain"]:
        aq.append(" OR ".join(f"\"URL\" ILIKE {_sq('%' + d + '%')}" for d in g["domain"][:20]))
    if hashes:
        aq.append("\"SHA256 Hash\" IN (" + ",".join(_sq(h) for h in g["sha256"] or hashes) + ")")
    out["qradar"] = ("SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, destinationip, username, "
                     "LOGSOURCENAME(logsourceid) AS logsource, QIDNAME(qid) AS event\nFROM events\nWHERE " +
                     "\n   OR ".join(f"({a})" for a in aq) + "\nLAST 30 DAYS")
    return out


# ------------------------------------------------------------------ CVE queries
def cve_queries(cve_ids, products=None):
    if not cve_ids:
        return {}
    cves = cve_ids[:30]
    prods = [p for p in (products or []) if p][:10]
    lst = ", ".join(_q(c) for c in cves)
    out = {
        "secops": "(" + " OR ".join(f'extensions.vulns.vulnerabilities.cve_id = {_q(c)}' for c in cves) + ")" +
                  ("\n// assets running affected products:\n// " + " OR ".join(f'principal.asset.software.name = /{re.escape(p)}/ nocase' for p in prods) if prods else ""),
        "yaral": (f"rule ti_vuln_exposure_{_rule_name(cves[0])[3:]} {{\n  meta:\n    author = \"ThreatPulse\"\n"
                  f"    description = \"Vulnerable assets / exploitation signals for {', '.join(cves[:5])}\"\n    severity = \"HIGH\"\n\n"
                  "  events:\n    (\n      " + "\n      or ".join(f'$e.extensions.vulns.vulnerabilities.cve_id = {_q(c)}' for c in cves) +
                  "\n      or " + "\n      or ".join(f'$e.security_result.rule_name = /{re.escape(c)}/ nocase' for c in cves[:10]) +
                  "\n    )\n    $e.principal.asset.hostname = $asset\n\n  match:\n    $asset over 24h\n\n  condition:\n    $e\n}"),
        "splunk": (f"| from datamodel:Vulnerabilities.Vulnerabilities | search cve IN ({lst}) OR signature IN ({lst})\n"
                   "| stats values(signature) as findings values(severity) as severity by dest\n\n"
                   f"`comment(\"IDS/WAF exploitation signatures\")`\nindex=* ({' OR '.join(_q(c) for c in cves)}) (sourcetype=*ids* OR sourcetype=*waf* OR sourcetype=*suricata* OR sourcetype=*snort*)\n"
                   "| stats count by src_ip dest_ip signature"),
        "sentinel": (f"let ti_cves = dynamic([{lst}]);\nDeviceTvmSoftwareVulnerabilities\n| where CveId in (ti_cves)\n"
                     "| summarize Devices=dcount(DeviceId), DeviceList=make_set(DeviceName, 50) by CveId, SoftwareName, SoftwareVersion\n\n"
                     "// Exploitation alerts that reference the CVEs\nSecurityAlert\n| where TimeGenerated > ago(30d)\n"
                     "| where Entities has_any (ti_cves) or Description has_any (ti_cves) or AlertName has_any (ti_cves)"),
        "elastic": f"vulnerability.id : ({' or '.join(_q(c) for c in cves)}) or rule.name : ({' or '.join('*' + c + '*' for c in cves[:10])})",
        "qradar": ("SELECT sourceip, destinationip, QIDNAME(qid) AS signature, COUNT(*) AS hits FROM events WHERE " +
                   " OR ".join(f"UTF8(payload) ILIKE {_sq('%' + c + '%')} OR QIDNAME(qid) ILIKE {_sq('%' + c + '%')}" for c in cves[:10]) +
                   " GROUP BY sourceip, destinationip, signature LAST 30 DAYS"),
    }
    return out


# ------------------------------------------------------------------ behaviour queries
def behaviour_queries(attack_types):
    out = {}
    for at in attack_types or []:
        p = ATTACK_PATTERNS.get(at)
        if not p or not p.get("behaviour"):
            continue
        b = dict(p["behaviour"])
        if "secops" in b and "yaral" not in b:
            name = _rule_name(p["name"])
            if "| match:" in b["secops"]:
                # aggregate-style search -> translate into a YARA-L rule skeleton
                body, *rest = b["secops"].split("\n| ")
                ev = " and ".join("$e." + c.strip() for c in re.split(r"\s+AND\s+", body))
                b["yaral"] = (f"rule {name}_behaviour {{\n  meta:\n    author = \"ThreatPulse\"\n    description = {_q(p['name'] + ' behaviour')}\n\n"
                              f"  events:\n    {ev}\n\n  // add match / outcome per your environment:\n  // " +
                              "\n  // ".join(rest) + "\n\n  condition:\n    $e\n}")
            else:
                ev = re.sub(r"\b(metadata|principal|target|network|security_result|extensions)\.", r"$e.\1.", b["secops"])
                ev = ev.replace(" AND ", "\n    and ").replace(" OR ", " or ").replace("NOT ", "not ")
                b["yaral"] = (f"rule {name}_behaviour {{\n  meta:\n    author = \"ThreatPulse\"\n    description = {_q(p['name'] + ' behaviour')}\n    severity = \"MEDIUM\"\n\n"
                              f"  events:\n    {ev}\n\n  condition:\n    $e\n}}")
        out[at] = {"name": p["name"], "queries": b}
    return out

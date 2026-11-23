# ⚡ ThreatPulse — Threat Intelligence Dashboard

A self-hosted threat intel dashboard. It pulls **news, vulnerabilities (CVEs) and IOCs** from many public sources, correlates them, and auto-generates **detailed threat reports**. Each report covers how the attack works step by step, maps it to MITRE ATT&CK and D3FEND, and lists IOCs, CVEs and mitigations. Every report also ships **ready-to-run SIEM hunt queries** for **Google SecOps (UDM search + YARA-L 2.0)**, Splunk, Microsoft Sentinel/Defender, Elastic and QRadar.

Pure Python standard library + vanilla JS. No dependencies, no build step.

## Quick start (no git needed)

1. **Install Python 3** from https://www.python.org/downloads/. On Windows, tick **"Add Python to PATH"** on the first installer screen.
2. **Download this project:** on GitHub click the green **Code** button, then **Download ZIP**, then unzip it.
3. **Double-click the launcher:**
   * Windows: `start-windows.bat`. If SmartScreen appears, click *More info*, then *Run anyway*.
   * macOS: `start-mac.command`. The first time, right-click it, choose *Open*, then confirm *Open*.
4. Your browser opens **http://127.0.0.1:8080** automatically. Keep the black terminal window open while you use the dashboard, and close it to stop.

**In VS Code:** open the folder (*File > Open Folder*), install the recommended **Python** extension when prompted, then open the *Run and Debug* view (Ctrl+Shift+D), pick **▶ Run ThreatPulse dashboard** and press **F5**.

Command line equivalents:

```bash
python3 run.py                    # http://127.0.0.1:8080  (collects every 15 min)
python3 run.py --demo             # also load clearly-labelled [DEMO] sample data
python3 run.py --collect-once     # one collection cycle, then exit (cron-friendly)
python3 run.py --host 0.0.0.0 --port 9000
python3 -m unittest discover -s tests
```

## Features

| Area | What you get |
|---|---|
| **Overview** | Live headline ticker, KPIs, activity timeline (hour / day / month / year, click to drill down), severity mix, trending attack patterns with sparklines, targeted industries / regions / actors, trending CVEs, latest CISA KEV, top reports, malware families |
| **Filters** (global) | Last 24h / 7d / 30d / 90d / 12 months / **all history**, a **specific year, month or day**, custom range · industry · region · attack type · free-text search. Filters persist across pages. |
| **Live Feed** | News & research from 20+ sources, auto-tagged with attack type, industry, region, actor, CVEs and extracted IOCs (defanged indicators supported) |
| **Threat Reports** | Auto-generated and refreshed every cycle: **Vulnerability** (KEV / trending CVEs), **Malware campaign** (IOC feeds + news), **Threat actor**, **Attack trend** (growth vs previous period). Each has an executive summary, key facts (CVSS, EPSS, KEV, due date, ransomware use), a step-by-step attack chain with ATT&CK techniques and D3FEND countermeasures, detection and mitigation guidance, **SIEM queries**, an IOC table with pivots (VirusTotal, urlscan, Shodan, AbuseIPDB, abuse.ch, CyberChef), targeting and sources. Export to PDF (print), Markdown or JSON. |
| **Vulnerabilities** | KEV, NVD, CVE.org and EPSS. Filter by KEV-only, ransomware use and CVSS; sort by EPSS / CVSS / mentions. Any CVE opens an on-demand report. |
| **IOCs** | ThreatFox, URLhaus, Feodo Tracker, OTX and article-extracted IOCs. Filter by type / source / malware, export CSV, one-click "Hunt these". |
| **Attack Patterns** | 13 playbooks (ransomware, phishing, edge-device exploitation, supply chain, infostealers, APT, cloud/identity, botnets, breaches, AI/LLM, mobile, web app, vulnerabilities), each with attack flow, detection, mitigations and behavioural hunt queries. Also an ATT&CK technique heat map weighted by current activity. |
| **Query Builder** | Paste any IOCs or CVEs (defanged OK) and get queries for all six SIEM formats, plus optional behavioural (TTP) hunts |
| **Sources** | Health of each collector, add/remove custom RSS feeds, "Collect now" |
| **Toolkit** | The essential analyst sites (CISA, NVD, EPSS, ATT&CK, D3FEND, ATLAS, CWE, NIST CSF, OWASP, SigmaHQ, abuse.ch, urlscan, Shodan, CyberChef…) |

**Live and historical:** a background scheduler refreshes every source (`TI_REFRESH_MINUTES`, default 15). The UI polls every 30 s and pops a "new items" toast. Nothing is ever deleted from the SQLite DB (`data/threatintel.db`), so old feed and reports stay available via "All time" or a year/month/day filter.

## Sources

* **News / research (RSS):** The Hacker News, BleepingComputer, Cybersecurity News, SecurityWeek, Dark Reading, Krebs on Security, The Record, Help Net Security, Infosecurity Magazine, SC Media, CISA Advisories, Unit 42, Cisco Talos, Microsoft Security, Google Threat Intel, SANS ISC, Securelist, ESET, Check Point Research, Sophos, CERT-In. Add more in `threatintel/config.py` or on the Sources page.
* **Vulnerabilities:** CISA KEV (with GitHub mirror fallback), NVD API 2.0, CVE.org `cvelistV5` (GitHub), FIRST EPSS.
* **IOCs:** abuse.ch ThreatFox, URLhaus, Feodo Tracker, AlienVault OTX, plus indicators extracted from articles.
* **Frameworks:** MITRE ATT&CK (enterprise), with links to D3FEND, ATLAS and CWE.

Optional free keys (environment variables):

| Variable | Unlocks |
|---|---|
| `ABUSECH_AUTH_KEY` | ThreatFox IOCs + URLhaus (https://auth.abuse.ch) |
| `OTX_API_KEY` | AlienVault OTX pulses + indicators |
| `NVD_API_KEY` | Higher NVD rate limits |

Other settings: `TI_HOST`, `TI_PORT`, `TI_DB_PATH`, `TI_REFRESH_MINUTES`, `TI_HTTP_TIMEOUT`, `TI_CVELIST_MAX`.

## SIEM queries

Every report contains three kinds of query, in each SIEM's default schema:

1. **IOC sweep:** IPs, domains, URLs and hashes from the report (UDM / CIM / ASIM+MDE / ECS / AQL).
2. **Vulnerability exposure:** assets with the CVE (`extensions.vulns.vulnerabilities.cve_id`, `DeviceTvmSoftwareVulnerabilities`, the Splunk Vulnerabilities data model…) plus IDS/WAF signature hits.
3. **Behavioural hunt:** TTP queries for the attack pattern (e.g. shadow-copy deletion, web-server child processes, ClickFix PowerShell, browser credential-store access), which work even with no IOCs.

Google SecOps output includes both a UDM search and a deployable **YARA-L 2.0 rule**. Adjust index, table and log-source names for your environment.

## Layout

```
run.py                     entry point
threatintel/
  config.py                sources, intervals, keys
  collectors.py            RSS, KEV, NVD, CVE List, EPSS, ThreatFox, URLhaus, Feodo, OTX, ATT&CK
  enrich.py                IOC / CVE / actor extraction; attack, industry, region classification
  knowledge.py             attack-pattern playbooks, ATT&CK/D3FEND mapping, taxonomies, toolkit
  queries.py               SecOps UDM + YARA-L, Splunk, Sentinel, Elastic, QRadar generators
  reports.py               report correlation engine
  scheduler.py, server.py  background refresh, JSON API + static UI
  demo.py                  [DEMO] sample data (RFC 5737 IPs, *.example domains)
web/                       index.html, styles.css, app.js
tests/                     unit tests
```

## API

`GET /api/stats | articles | cves | iocs | iocs/export | reports | reports/<id> | patterns | sources | updates | meta | toolkit` (all accept `from`, `to`, `industry`, `region`, `attack`, `q`). `POST /api/collect`, `POST /api/query-builder {text, attack_types}`, `POST /api/sources {name,url}`, `DELETE /api/sources/<name>`.

> Demo data is only loaded with `--demo`. To remove it, delete `data/threatintel.db` and restart without the flag.

"""Clearly-labelled DEMO data for offline previews.

Every item is prefixed "[DEMO]", comes from source "DEMO Feed", and uses
documentation-only IP ranges (RFC 5737) and *.example domains, so nothing
can be mistaken for real intelligence. Real collectors run alongside it.
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from . import collectors, db, reports

TEMPLATES = [
    ("Ransomware gang hits {ind_noun} in {country}, data leaked on extortion site",
     "A double extortion ransomware attack disrupted operations at a {ind_noun} in {country}. Operators used a VPN flaw {cve} for initial access, deployed Cobalt Strike and exfiltrated data with rclone before encryption. C2: {ip1}, {dom1}."),
    ("Phishing campaign uses QR codes and AiTM kit to steal Microsoft 365 sessions at {ind_noun}s",
     "An adversary-in-the-middle phishing campaign targets {ind_noun}s across {country}. Lures with QR codes redirect to {dom1}, harvesting session cookies and bypassing MFA."),
    ("Critical {vendor} flaw {cve} actively exploited in the wild",
     "Attackers are actively exploiting {cve}, a pre-auth remote code execution vulnerability in {vendor} appliances. Web shells were dropped on edge devices at {ind_noun}s in {country}. Exploitation traffic from {ip1} and {ip2}."),
    ("Malicious npm packages steal developer secrets in supply chain attack",
     "Researchers found typosquatted npm packages with postinstall scripts that exfiltrate cloud keys and GitHub tokens to {dom1}. Payload SHA256 {sha}."),
    ("Lumma infostealer spread via fake CAPTCHA ClickFix pages targeting {country}",
     "A malvertising campaign uses fake CAPTCHA pages to trick users into running PowerShell that installs the Lumma infostealer, stealing browser passwords and cookies. C2 {dom1}, {ip1}."),
    ("{actor} targets {ind_noun} networks in cyber espionage campaign",
     "State-sponsored threat actor {actor} has been linked to an espionage campaign against {ind_noun}s in {country}, exploiting {cve} and using living-off-the-land techniques. Infrastructure: {ip1}, {dom1}."),
    ("Password spraying attacks hit cloud identity providers at {ind_noun}s",
     "A large password spray and credential stuffing campaign targeted Entra ID and Okta tenants of {ind_noun}s in {country} from residential proxy IPs such as {ip1}."),
    ("New Mirai botnet variant exploits router flaws for DDoS attacks",
     "A Mirai-based botnet is exploiting IoT router vulnerabilities including {cve} to launch DDoS attacks against {ind_noun}s in {country}. C2 at {ip1}."),
    ("Data breach at {ind_noun} exposes millions of customer records in {country}",
     "A data breach at a {ind_noun} in {country} exposed personal information of customers after attackers accessed a misconfigured cloud database."),
    ("Prompt injection flaw in AI agent lets attackers exfiltrate data",
     "Researchers disclosed an indirect prompt injection issue in an LLM-powered AI agent that allows data leakage through rendered links to {dom1}."),
    ("SQL injection in popular WordPress plugin exploited, {cve}",
     "A SQL injection vulnerability {cve} in a widely used WordPress plugin is being exploited to create admin accounts on e-commerce sites in {country}."),
    ("Android banking trojan spreads via smishing in {country}",
     "A new Android banking malware is distributed via SMS phishing, abusing accessibility services to steal OTPs from banking app users in {country}. C2 {dom1}."),
]
IND = [("hospital", "Healthcare"), ("bank", "Finance"), ("government agency", "Government"), ("university", "Education"),
       ("manufacturing firm", "Manufacturing"), ("energy utility", "Energy & Utilities"), ("telecom carrier", "Telecommunications"),
       ("online retailer", "Retail & E-commerce"), ("software company", "Technology"), ("airline", "Transportation & Logistics"),
       ("insurance company", "Finance"), ("law firm", "Legal & Professional")]
COUNTRIES = ["India", "the United States", "Germany", "the United Kingdom", "Japan", "Australia", "Brazil", "Singapore",
             "Israel", "Canada", "France", "South Africa", "Saudi Arabia", "Taiwan"]
ACTORS = ["APT29", "Volt Typhoon", "Lazarus", "Kimsuky", "Sandworm", "Mustang Panda", "Transparent Tribe", "MuddyWater"]
VENDORS = ["Fortinet FortiGate", "Ivanti Connect Secure", "Citrix NetScaler", "Palo Alto PAN-OS", "SonicWall", "Cisco ASA"]
MALWARE = ["DEMO.LummaStealer", "DEMO.CobaltStrike", "DEMO.Mirai", "DEMO.AsyncRAT", "DEMO.QakBot", "DEMO.RedLine"]


def _ip(r):
    return f"{r.choice(['192.0.2', '198.51.100', '203.0.113'])}.{r.randint(1, 254)}"


def _dom(r):
    return f"{r.choice(['secure', 'login', 'cdn', 'update', 'auth', 'files'])}-{r.randint(100, 999)}.demo-c2.example"


def load(n=260, days=200):
    r = random.Random(42)
    now = datetime.now(timezone.utc)
    kev = [x["cve_id"] for x in db.query("SELECT cve_id FROM cves WHERE kev=1 ORDER BY kev_added DESC LIMIT 40")] or \
          ["CVE-2026-0001", "CVE-2026-0002", "CVE-2025-0003"]
    for i in range(n):
        # skew toward recent dates so trends look realistic
        age = min(days, int(r.expovariate(1 / 35)))
        pub = now - timedelta(days=age, hours=r.randint(0, 23), minutes=r.randint(0, 59))
        t, body = r.choice(TEMPLATES)
        ind_noun, _ = r.choice(IND)
        ip1, ip2, dom1 = _ip(r), _ip(r), _dom(r)
        sha = hashlib.sha256(f"demo{i}".encode()).hexdigest()
        ctx = dict(ind_noun=ind_noun, country=r.choice(COUNTRIES), cve=r.choice(kev), actor=r.choice(ACTORS),
                   vendor=r.choice(VENDORS), ip1=ip1.replace(".", "[.]", 1), ip2=ip2, dom1=dom1.replace(".", "[.]"), sha=sha)
        title = "[DEMO] " + t.format(**ctx)
        collectors.store_article("DEMO Feed", title, f"https://demo.example/article/{i}", body.format(**ctx),
                                 pub.strftime("%Y-%m-%dT%H:%M:%SZ"), uid=f"demo-{i}")
    rows = []
    for i in range(900):
        age = min(days, int(r.expovariate(1 / 30)))
        seen = (now - timedelta(days=age, hours=r.randint(0, 23))).strftime("%Y-%m-%dT%H:%M:%SZ")
        mal = r.choice(MALWARE)
        kind = r.choice(["ip", "ip", "domain", "url", "sha256"])
        val = {"ip": _ip(r), "domain": _dom(r), "url": f"http://{_dom(r)}/{r.choice(['bin', 'gate.php', 'x86', 'load'])}",
               "sha256": hashlib.sha256(f"ioc{i}".encode()).hexdigest()}[kind]
        rows.append((val, kind, "DEMO IOC Feed", mal, r.choice(["botnet_cc", "payload_delivery", "payload"]),
                     r.choice([50, 75, 100]), db.j(["demo"]), seen, seen, "https://demo.example/ioc"))
    collectors._store_iocs("DEMO IOC Feed", rows)
    collectors.set_status("DEMO Feed", "news", "https://demo.example", True, n, "Sample data for offline preview")
    collectors.set_status("DEMO IOC Feed", "ioc", "https://demo.example", True, len(rows), "Sample IOCs (RFC 5737 / .example)")
    collectors.harvest_article_iocs()
    print("demo data loaded; reports:", reports.rebuild_all())

"""Runtime configuration (override with environment variables)."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("TI_DB_PATH", os.path.join(BASE_DIR, "data", "threatintel.db"))
WEB_DIR = os.path.join(BASE_DIR, "web")
HOST = os.environ.get("TI_HOST", "127.0.0.1")
PORT = int(os.environ.get("TI_PORT", "8080"))

# How often (minutes) the background scheduler refreshes all sources
REFRESH_MINUTES = int(os.environ.get("TI_REFRESH_MINUTES", "15"))
HTTP_TIMEOUT = int(os.environ.get("TI_HTTP_TIMEOUT", "25"))
USER_AGENT = os.environ.get("TI_USER_AGENT", "ThreatPulse/1.0 (+threat-intel-dashboard)")

# Optional API keys - sources that need them are skipped when unset
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "")   # https://auth.abuse.ch (free)

# Max CVE records to pull from the CVE List delta per run
CVELIST_MAX = int(os.environ.get("TI_CVELIST_MAX", "120"))

# ---------------------------------------------------------------------------
# News / research RSS feeds. Add your own here (or via the Sources page).
# ---------------------------------------------------------------------------
RSS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Cybersecurity News", "https://cybersecuritynews.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/"),
    ("SC Media", "https://www.scworld.com/feed"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Google Threat Intel", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Securelist", "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("Sophos News", "https://news.sophos.com/en-us/feed/"),
    ("CERT-In (India)", "https://www.cert-in.org.in/RSSFeed.jsp"),
]

# Structured sources (primary URL, then mirrors tried in order)
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVELIST_DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

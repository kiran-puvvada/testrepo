"""Extraction & classification: IOCs, CVEs, actors, attack types, industries, regions."""
import html
import re

from .knowledge import ATTACK_PATTERNS, INDUSTRIES, REGIONS

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\[?\.\]?){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
# Defanged domains such as evil[.]com or hxxp://
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+(?:\[\.\]|\.))+(?:[a-z]{2,24})\b", re.I)
DEFANGED_HINT = re.compile(r"\[\.\]|hxxp|\(\.\)", re.I)
ACTOR_RE = re.compile(
    r"\b(APT\s?\d{1,3}|UNC\d{3,5}|TA\d{3,4}|FIN\d{1,2}|Storm-\d{3,4}|[A-Z][a-z]+ (?:Typhoon|Blizzard|Sleet|Sandstorm|Tempest|Panda|Bear|Kitten|Chollima|Spider))\b")
KNOWN_ACTORS = ["Lazarus", "Kimsuky", "Sandworm", "Turla", "Gamaredon", "MuddyWater", "Scattered Spider",
                "Mustang Panda", "SideWinder", "Transparent Tribe", "OilRig", "Andariel", "BlueNoroff",
                "Cl0p", "LockBit", "Akira", "Qilin", "Play", "Black Basta", "RansomHub", "ShinyHunters",
                "Lapsus$", "Volt Typhoon", "Salt Typhoon", "Midnight Blizzard", "Charming Kitten"]

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")

BENIGN_DOMAINS = {"github.com", "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com",
                  "google.com", "microsoft.com", "apple.com", "cisa.gov", "nist.gov", "mitre.org"}


def clean_text(s):
    if not s:
        return ""
    s = html.unescape(TAG_RE.sub(" ", s))
    return WS_RE.sub(" ", s).strip()


def refang(v):
    return v.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http").replace("[:]", ":")


def extract_cves(text):
    return sorted({m.upper() for m in CVE_RE.findall(text or "")})


def extract_iocs(text):
    """Conservative IOC extraction from prose (news). Domains only when defanged."""
    text = text or ""
    out = []
    seen = set()

    def add(t, v):
        if v not in seen:
            seen.add(v)
            out.append({"type": t, "value": v})

    for h in SHA256_RE.findall(text):
        add("sha256", h.lower())
    for h in SHA1_RE.findall(text):
        if not any(h.lower() in s for s in seen):
            add("sha1", h.lower())
    for h in MD5_RE.findall(text):
        if not any(h.lower() in s for s in seen):
            add("md5", h.lower())
    for ip in IPV4_RE.findall(text):
        ip = refang(ip)
        if not (ip.startswith(("10.", "127.", "192.168.", "0.")) or ip.count(".") != 3):
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and not re.match(r"^\d+\.\d+\.\d+\.0$", ip):
                add("ip", ip)
    if DEFANGED_HINT.search(text):
        for d in DOMAIN_RE.findall(text):
            if "[.]" in d or "(.)" in d:
                d = refang(d).lower()
                if d not in BENIGN_DOMAINS:
                    add("domain", d)
    return out[:200]


def extract_actors(text):
    found = {m.strip() for m in ACTOR_RE.findall(text or "")}
    low = (text or "").lower()
    for a in KNOWN_ACTORS:
        if re.search(r"\b" + re.escape(a.lower()) + r"\b", low):
            found.add(a)
    return sorted(found)[:10]


_KW_CACHE = {}


def _kw_re(k):
    r = _KW_CACHE.get(k)
    if r is None:
        pre = r"(?<![a-z0-9])" if k[:1].isalnum() else ""
        suf = r"(?![a-z0-9])" if k[-1:].isalnum() else ""
        r = _KW_CACHE[k] = re.compile(pre + re.escape(k.strip()) + suf)
    return r


def _has(k, low):
    return _kw_re(k).search(low) is not None


def _match(text, mapping):
    low = " " + (text or "").lower() + " "
    hits = []
    for name, kws in mapping.items():
        score = sum(1 for k in kws if _has(k, low))
        if score:
            hits.append((score, name))
    hits.sort(reverse=True)
    return [h[1] for h in hits]


def classify_attack(text):
    low = " " + (text or "").lower() + " "
    scores = []
    for key, p in ATTACK_PATTERNS.items():
        s = sum(2 if " " in k else 1 for k in p["keywords"] if _has(k, low))
        if s:
            scores.append((s, key))
    scores.sort(reverse=True)
    types = [k for _, k in scores[:3]]
    # "vulnerability" is a generic fallback - drop it if something more specific matched
    if len(types) > 1 and "vulnerability" in types:
        types.remove("vulnerability")
    return types


def classify_industries(text):
    return _match(text, INDUSTRIES)[:4]


def classify_regions(text):
    return _match(text, REGIONS)[:4]


def severity_for(text, cves=None, kev_hit=False):
    low = (text or "").lower()
    if kev_hit or any(k in low for k in ("actively exploited", "zero-day", "0-day", "exploited in the wild", "emergency")):
        return "critical"
    if any(k in low for k in ("ransomware", "critical", "remote code execution", "rce", "breach", "nation-state")):
        return "high"
    if cves or any(k in low for k in ("vulnerability", "malware", "phishing", "stealer", "trojan", "botnet", "exploit", "spyware", "backdoor")):
        return "medium"
    return "low"


def cvss_severity(score):
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def ioc_type(value):
    v = value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+(:\d+)?", v):
        return "ip"
    if v.startswith(("http://", "https://")):
        return "url"
    return "domain"

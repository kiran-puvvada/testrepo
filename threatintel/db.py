"""SQLite storage. Nothing is ever purged, so historical feed stays searchable."""
import json
import os
import sqlite3
import threading

from . import config

_local = threading.local()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE,
    source TEXT, title TEXT, url TEXT, summary TEXT,
    published TEXT, fetched TEXT,
    attack_types TEXT, industries TEXT, regions TEXT,
    cves TEXT, iocs TEXT, actors TEXT, severity TEXT
);
CREATE INDEX IF NOT EXISTS ix_articles_pub ON articles(published);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT, vendor TEXT, product TEXT,
    cvss REAL, severity TEXT, vector TEXT, cwe TEXT,
    epss REAL, epss_pct REAL,
    kev INTEGER DEFAULT 0, kev_added TEXT, kev_due TEXT, ransomware TEXT,
    required_action TEXT, published TEXT, updated TEXT, sources TEXT,
    refs TEXT, attack_types TEXT, mentions INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_cves_pub ON cves(published);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT, type TEXT, source TEXT,
    malware TEXT, threat_type TEXT, confidence INTEGER,
    tags TEXT, first_seen TEXT, last_seen TEXT, reference TEXT,
    UNIQUE(value, source)
);
CREATE INDEX IF NOT EXISTS ix_iocs_seen ON iocs(first_seen);
CREATE INDEX IF NOT EXISTS ix_iocs_malware ON iocs(malware);

CREATE TABLE IF NOT EXISTS techniques (
    tid TEXT PRIMARY KEY, name TEXT, tactics TEXT, description TEXT, url TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    rid TEXT PRIMARY KEY, kind TEXT, title TEXT, created TEXT, updated TEXT,
    severity TEXT, score REAL, data TEXT
);

CREATE TABLE IF NOT EXISTS source_status (
    name TEXT PRIMARY KEY, kind TEXT, url TEXT, last_run TEXT, last_ok TEXT,
    items INTEGER, total INTEGER, status TEXT, message TEXT
);

CREATE TABLE IF NOT EXISTS custom_feeds (
    name TEXT PRIMARY KEY, url TEXT
);
"""


def conn():
    c = getattr(_local, "conn", None)
    if c is None:
        os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
        c = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        _local.conn = c
    return c


def init():
    with _lock:
        conn().executescript(SCHEMA)
        conn().commit()


def write(sql, params=()):
    with _lock:
        cur = conn().execute(sql, params)
        conn().commit()
        return cur


def write_many(sql, rows):
    with _lock:
        cur = conn().executemany(sql, rows)
        conn().commit()
        return cur.rowcount


def query(sql, params=()):
    return [dict(r) for r in conn().execute(sql, params).fetchall()]


def one(sql, params=()):
    r = conn().execute(sql, params).fetchone()
    return dict(r) if r else None


def j(v):
    return json.dumps(v or [])


def unj(v, default=None):
    if not v:
        return default if default is not None else []
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return default if default is not None else []

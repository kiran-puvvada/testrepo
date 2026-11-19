"""Background refresh loop: pulls every source, enriches, rebuilds reports."""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import collectors as C, config, reports

log = logging.getLogger("scheduler")

STATE = {"running": False, "last_start": None, "last_end": None, "last_result": {}, "next_run": None}
_run_lock = threading.Lock()


def run_cycle():
    if not _run_lock.acquire(blocking=False):
        return {"skipped": "already running"}
    try:
        STATE.update(running=True, last_start=C.now_iso())
        res = {}
        # Frameworks + vulnerability catalogs first (news enrichment checks KEV)
        res["mitre"] = C.collect_mitre()
        res["kev"] = C.collect_kev()
        res["nvd"] = C.collect_nvd()
        res["cvelist"] = C.collect_cvelist()
        # News feeds in parallel
        with ThreadPoolExecutor(max_workers=8) as ex:
            res["news"] = sum(ex.map(lambda f: C.collect_rss(*f), C.all_rss_feeds()))
        # IOC feeds
        res["threatfox"] = C.collect_threatfox()
        res["urlhaus"] = C.collect_urlhaus()
        res["feodo"] = C.collect_feodo()
        res["otx"] = C.collect_otx()
        res["news_iocs"] = C.harvest_article_iocs()
        # Enrichment
        res["cve_enriched"] = C.enrich_cves_from_cvelist()
        res["epss"] = C.collect_epss()
        res["reports"] = reports.rebuild_all()
        STATE["last_result"] = res
        log.info("cycle complete: %s", res)
        return res
    except Exception as e:  # noqa: BLE001
        log.exception("cycle failed")
        STATE["last_result"] = {"error": str(e)}
        return STATE["last_result"]
    finally:
        STATE.update(running=False, last_end=C.now_iso())
        _run_lock.release()


def run_async():
    t = threading.Thread(target=run_cycle, daemon=True)
    t.start()
    return t


def loop():
    while True:
        run_cycle()
        STATE["next_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + config.REFRESH_MINUTES * 60))
        time.sleep(config.REFRESH_MINUTES * 60)


def start():
    threading.Thread(target=loop, daemon=True, name="ti-scheduler").start()

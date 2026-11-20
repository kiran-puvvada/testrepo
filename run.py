#!/usr/bin/env python3
"""ThreatPulse - threat intelligence dashboard.

    python3 run.py                 # start dashboard + background collectors
    python3 run.py --collect-once  # run one collection cycle and exit
    python3 run.py --no-collect    # serve existing data only
    python3 run.py --demo          # load clearly-labelled DEMO data (offline preview)
"""
import argparse
import logging

from threatintel import config, db, scheduler, server


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.PORT)
    ap.add_argument("--collect-once", action="store_true", help="run one collection cycle and exit")
    ap.add_argument("--no-collect", action="store_true", help="do not run background collectors")
    ap.add_argument("--demo", action="store_true", help="load sample DEMO data for an offline preview")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init()
    if a.demo:
        from threatintel import demo
        demo.load()
    if a.collect_once:
        print(scheduler.run_cycle())
        return
    if not a.no_collect:
        scheduler.start()
    server.serve(a.host, a.port)


if __name__ == "__main__":
    main()

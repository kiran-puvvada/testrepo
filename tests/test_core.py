import os
import tempfile
import unittest

os.environ["TI_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

from threatintel import collectors, db, enrich, queries, reports  # noqa: E402


class EnrichTests(unittest.TestCase):
    def test_extract_cves(self):
        self.assertEqual(enrich.extract_cves("fix cve-2024-3400 and CVE-2023-12345"), ["CVE-2023-12345", "CVE-2024-3400"])

    def test_extract_defanged_iocs(self):
        found = {(i["type"], i["value"]) for i in enrich.extract_iocs("C2 at 203.0.113[.]5 and evil[.]example " + "a" * 64)}
        self.assertIn(("ip", "203.0.113.5"), found)
        self.assertIn(("domain", "evil.example"), found)
        self.assertIn(("sha256", "a" * 64), found)

    def test_keyword_word_boundaries(self):
        # "apt" must not match inside "captcha"
        self.assertNotIn("apt_espionage", enrich.classify_attack("fake captcha pages deliver Lumma infostealer"))
        self.assertIn("infostealer", enrich.classify_attack("fake captcha pages deliver Lumma infostealer"))

    def test_industry_region(self):
        self.assertIn("Healthcare", enrich.classify_industries("ransomware hits hospital"))
        self.assertIn("South Asia", enrich.classify_regions("attack on Indian banks"))


class QueryTests(unittest.TestCase):
    def test_ioc_queries_all_siems(self):
        q = queries.ioc_queries([{"type": "ip", "value": "203.0.113.5"}, {"type": "domain", "value": "evil.example"},
                                 {"type": "sha256", "value": "a" * 64}], "Test Report")
        for k in ("secops", "yaral", "splunk", "sentinel", "elastic", "qradar"):
            self.assertIn(k, q)
            self.assertIn("203.0.113.5", q[k])
        self.assertTrue(q["yaral"].startswith("rule ti_test_report"))

    def test_cve_queries(self):
        q = queries.cve_queries(["CVE-2024-3400"], ["PAN-OS"])
        self.assertIn('extensions.vulns.vulnerabilities.cve_id = "CVE-2024-3400"', q["secops"])
        self.assertIn("DeviceTvmSoftwareVulnerabilities", q["sentinel"])


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init()

    def test_feed_parse_store_and_report(self):
        rss = b"""<?xml version="1.0"?><rss><channel><item><title>Ransomware gang exploits CVE-2099-0001 at hospital in Germany</title>
        <link>https://x.example/a</link><description>C2 198.51.100[.]7 used by LockBit affiliates</description>
        <pubDate>Tue, 18 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>"""
        items = collectors.parse_feed(rss)
        self.assertEqual(len(items), 1)
        self.assertEqual(collectors.store_article("Test", items[0]["title"], items[0]["url"], items[0]["summary"], items[0]["published"]), 1)
        a = db.one("SELECT * FROM articles WHERE source='Test'")
        self.assertIn("ransomware", db.unj(a["attack_types"]))
        self.assertIn("Healthcare", db.unj(a["industries"]))
        self.assertEqual(a["published"], "2026-11-18T10:00:00Z")
        c = db.one("SELECT * FROM cves WHERE cve_id='CVE-2099-0001'")
        title, sev, score, data = reports.cve_report_data(c)
        self.assertTrue(data["chain"])
        self.assertIn("198.51.100.7", data["queries"]["ioc"]["splunk"])

    def test_atom_parse(self):
        atom = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>T</title><link href="https://x.example/b"/>
        <summary>s</summary><updated>2026-11-01T00:00:00Z</updated></entry></feed>"""
        self.assertEqual(collectors.parse_feed(atom)[0]["url"], "https://x.example/b")


if __name__ == "__main__":
    unittest.main()

"""Checkpoint 3 tests: MAC analysis, OUI DB build/parse, and lookups.

No network: parsing uses sample CSV text, lookups use a temp SQLite DB, and
the API fallback is injected. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import tempfile
import unittest

from wifi_scanner.scanner.models import Host
from wifi_scanner.scanner.oui import (
    OuiLookup,
    build_oui_db,
    clean_mac_hex,
    first_octet,
    is_locally_administered,
    is_multicast,
    oui_prefix,
    parse_oui_csv,
)

SAMPLE_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,789A18,Routerboard.com,Riga LV\n"
    "MA-L,001122,Acme Networks,Somewhere\n"
    'MA-L,AABBCC,"Vendor, Inc.",City\n'
)


class TestMacBits(unittest.TestCase):
    def test_clean_mac_hex(self):
        self.assertEqual(clean_mac_hex("AA:BB:CC:DD:EE:FF"), "aabbccddeeff")
        self.assertEqual(clean_mac_hex("aa-bb-cc-dd-ee-ff"), "aabbccddeeff")

    def test_oui_prefix(self):
        self.assertEqual(oui_prefix("78:9a:18:be:5c:41"), "789a18")
        self.assertIsNone(oui_prefix("78:9a"))

    def test_first_octet(self):
        self.assertEqual(first_octet("78:9a:18:..."), 0x78)
        self.assertIsNone(first_octet("7"))

    def test_locally_administered_true(self):
        # 0x4a -> bit 0x02 set
        self.assertTrue(is_locally_administered("4a:da:eb:74:fb:b5"))
        self.assertTrue(is_locally_administered("d6:8e:d3:a9:b6:ef"))

    def test_locally_administered_false_for_real_oui(self):
        self.assertFalse(is_locally_administered("78:9a:18:be:5c:41"))
        self.assertFalse(is_locally_administered("38:ba:f8:fa:8d:86"))

    def test_multicast_detection(self):
        self.assertTrue(is_multicast("01:00:5e:00:00:fb"))   # 0x01 set
        self.assertFalse(is_multicast("78:9a:18:be:5c:41"))


class TestParseOuiCsv(unittest.TestCase):
    def test_parses_prefixes(self):
        mapping = parse_oui_csv(SAMPLE_CSV)
        self.assertEqual(mapping["789a18"], "Routerboard.com")
        self.assertEqual(mapping["001122"], "Acme Networks")

    def test_handles_quoted_commas(self):
        mapping = parse_oui_csv(SAMPLE_CSV)
        self.assertEqual(mapping["aabbcc"], "Vendor, Inc.")

    def test_skips_header_and_short_rows(self):
        mapping = parse_oui_csv("Registry,Assignment,Org\nMA-L,short\n")
        self.assertEqual(mapping, {})


class TestOuiLookup(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        build_oui_db(self.db_path, parse_oui_csv(SAMPLE_CSV))

    def tearDown(self):
        os.unlink(self.db_path)

    def test_local_hit(self):
        lk = OuiLookup(db_path=self.db_path)
        info = lk.lookup("78:9a:18:be:5c:41")
        self.assertEqual(info.vendor, "Routerboard.com")
        self.assertEqual(info.source, "local")
        self.assertFalse(info.randomized)
        lk.close()

    def test_randomized_returns_no_vendor_and_skips_api(self):
        calls = []

        def fetcher(mac):
            calls.append(mac)
            return "ShouldNotBeUsed"

        lk = OuiLookup(db_path=self.db_path, enable_api=True, api_fetcher=fetcher)
        info = lk.lookup("4a:da:eb:74:fb:b5")
        self.assertTrue(info.randomized)
        self.assertIsNone(info.vendor)
        self.assertEqual(calls, [])          # API never consulted
        lk.close()

    def test_api_fallback_when_not_in_db(self):
        lk = OuiLookup(
            db_path=self.db_path, enable_api=True,
            api_fetcher=lambda mac: "Cloud Vendor",
        )
        info = lk.lookup("fc:ee:dd:11:22:33")   # globally-administered, not in DB
        self.assertFalse(info.randomized)        # 0xfc has the LAA bit clear
        self.assertEqual(info.vendor, "Cloud Vendor")
        self.assertEqual(info.source, "api")
        lk.close()

    def test_api_disabled_by_default(self):
        lk = OuiLookup(db_path=self.db_path)     # enable_api defaults False
        info = lk.lookup("00:99:88:77:66:55")    # not in DB
        self.assertIsNone(info.vendor)
        self.assertIsNone(info.source)
        lk.close()

    def test_cache_memoizes(self):
        lk = OuiLookup(db_path=self.db_path)
        a = lk.lookup("78:9a:18:be:5c:41")
        b = lk.lookup("78:9A:18:BE:5C:41")       # different case, same MAC
        self.assertIs(a, b)
        lk.close()

    def test_annotate_sets_vendor(self):
        lk = OuiLookup(db_path=self.db_path)
        host = Host(ip="10.8.50.1", mac="78:9a:18:be:5c:41")
        lk.annotate(host)
        self.assertEqual(host.vendor, "Routerboard.com")
        self.assertNotIn("RANDOMIZED_MAC", host.risk_flags)
        lk.close()

    def test_annotate_flags_randomized(self):
        lk = OuiLookup(db_path=self.db_path)
        host = Host(ip="10.8.51.5", mac="4a:da:eb:74:fb:b5")
        lk.annotate(host)
        self.assertIsNone(host.vendor)
        self.assertIn("RANDOMIZED_MAC", host.risk_flags)
        # idempotent — annotating twice doesn't duplicate the flag
        lk.annotate(host)
        self.assertEqual(host.risk_flags.count("RANDOMIZED_MAC"), 1)
        lk.close()

    def test_annotate_no_ops_for_mac_known_false(self):
        # ICMP-discovered hosts never attempted a MAC — OUI lookup must not
        # guess a vendor or flag RANDOMIZED_MAC for them.
        lk = OuiLookup(db_path=self.db_path)
        host = Host(ip="10.8.9.20", mac="", mac_known=False)
        lk.annotate(host)
        self.assertIsNone(host.vendor)
        self.assertNotIn("RANDOMIZED_MAC", host.risk_flags)
        lk.close()


class TestMissingDb(unittest.TestCase):
    def test_lookup_without_db_still_detects_randomized(self):
        lk = OuiLookup(db_path="/nonexistent/path/oui.db")
        self.assertFalse(lk.has_db)
        info = lk.lookup("4a:da:eb:74:fb:b5")
        self.assertTrue(info.randomized)
        self.assertIsNone(info.vendor)
        lk.close()


if __name__ == "__main__":
    unittest.main()
